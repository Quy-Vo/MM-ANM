import base64
import hashlib
import json
import os
import socket
import sys
import threading
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import crypto
import handshake
from config import HOST, PORT, CHUNK_SIZE, MAX_FILE_SIZE, DOWNLOAD_DIR, MEMBERS_FILE, KEYS_DIR
from protocol import send_msg, recv_msg
from file_transfer import sha256_file, validate_file

def load_members():
    try:
        with open(MEMBERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Không đọc được members.json: {exc}")
    if not isinstance(data, dict):
        raise RuntimeError("members.json phải là JSON object.")
    for name, item in data.items():
        if not isinstance(item, dict) or not item.get("mssv") or not item.get("public_key"):
            raise RuntimeError(f"Thiếu mssv/public_key cho thành viên {name}.")
        try:
            pub = bytes.fromhex(item["public_key"])
        except ValueError:
            raise RuntimeError(f"Khóa công khai của {name} không phải hex.")
        if len(pub) != 32:
            raise RuntimeError(f"Khóa công khai của {name} phải dài 32 byte.")
    return data

def load_private_key(name):
    path = os.path.join(KEYS_DIR, f"{name}_ed25519_private.pem")
    try:
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    except OSError as exc:
        raise RuntimeError(f"Không đọc được khóa riêng {path}: {exc}")
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("Khóa riêng không phải Ed25519.")
    return key

def aad_for(session_id, sender, recipient, kind):
    return f"E2E-CHAT-V1|{session_id}|{sender}|{recipient}|{kind}".encode("utf-8")

class ChatClient:
    def __init__(self, name):
        self.name = name
        self.members = load_members()
        if name not in self.members:
            raise RuntimeError(f"Chưa có thành viên '{name}' trong members.json.")
        self.mssv = self.members[name]["mssv"]
        self.signing_private_key = load_private_key(name)
        own_pub = self.signing_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()
        if own_pub != self.members[name]["public_key"].lower():
            raise RuntimeError("Khóa riêng và khóa công khai trong members.json không khớp.")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))
        self.send_lock = threading.Lock()
        self.state_lock = threading.Lock()
        self.pending_initiator = {}
        self.pending_responder = {}
        self.sessions = {}
        self.incoming_files = {}
        send_msg(self.sock, {"type": "register", "name": name})
        self.receiver = threading.Thread(target=self.receive_loop, daemon=True)
        self.receiver.start()

    def send_packet(self, packet):
        with self.send_lock:
            send_msg(self.sock, packet)

    def send_handshake(self, peer, message):
        packet = dict(message)
        packet["from"] = self.name
        packet["to"] = peer
        self.send_packet(packet)

    def connect_peer(self, peer):
        if peer == self.name:
            print("Không thể kết nối với chính mình.")
            return
        if peer not in self.members:
            print(f"'{peer}' chưa được khai báo trong members.json.")
            return
        with self.state_lock:
            if peer in self.sessions:
                print(f"Đã có phiên bảo mật với {peer}.")
                return
            if peer in self.pending_initiator or peer in self.pending_responder:
                print(f"Đang bắt tay với {peer}.")
                return
        peer_mssv = self.members[peer]["mssv"]
        group_mssvs = tuple(item["mssv"] for item in self.members.values())
        state, hello = handshake.create_hello(self.mssv, peer_mssv, group_mssvs)
        with self.state_lock:
            self.pending_initiator[peer] = state
        self.send_handshake(peer, hello)
        print(f"Đã gửi HELLO tới {peer}; chờ xác thực.")

    def handle_handshake(self, packet):
        typ = packet.get("type")
        peer = packet.get("from")
        if not isinstance(peer, str) or peer not in self.members or peer == self.name:
            print(f"\n[SECURITY] Từ chối handshake từ thành viên không được cấu hình: {peer}\n> ", end="", flush=True)
            return
        peer_pub = bytes.fromhex(self.members[peer]["public_key"])
        peer_mssv = self.members[peer]["mssv"]
        try:
            if typ == "HELLO":
                if packet.get("initiator_mssv") != peer_mssv or packet.get("responder_mssv") != self.mssv:
                    raise handshake.HandshakeError("MSSV trong HELLO không khớp cấu hình tin cậy.")
                group_mssvs = tuple(item["mssv"] for item in self.members.values())
                state, reply = handshake.accept_hello(packet, self.signing_private_key, group_mssvs)
                with self.state_lock:
                    self.pending_responder[peer] = state
                self.send_handshake(peer, reply)
                print(f"\n[HANDSHAKE] Nhận HELLO từ {peer}; đã gửi HELLO_REPLY.\n> ", end="", flush=True)
            elif typ == "HELLO_REPLY":
                if packet.get("initiator_mssv") != self.mssv or packet.get("responder_mssv") != peer_mssv:
                    raise handshake.HandshakeError("MSSV trong HELLO_REPLY không khớp cấu hình tin cậy.")
                with self.state_lock:
                    state = self.pending_initiator.get(peer)
                if state is None:
                    raise handshake.HandshakeError("Không có HELLO đang chờ tương ứng.")
                auth, keys = handshake.verify_reply_and_create_auth(
                    state, packet, peer_pub, self.signing_private_key
                )
                with self.state_lock:
                    self.sessions[peer] = keys
                    self.pending_initiator.pop(peer, None)
                self.send_handshake(peer, auth)
                print(f"\n[HANDSHAKE OK] Đã xác thực {peer}; khóa phiên phía gửi/nhận đã tạo.\n> ", end="", flush=True)
            elif typ == "AUTH":
                with self.state_lock:
                    state = self.pending_responder.get(peer)
                if state is None:
                    raise handshake.HandshakeError("Không có HELLO_REPLY đang chờ AUTH.")
                keys = handshake.verify_auth_and_derive_keys(state, packet, peer_pub)
                with self.state_lock:
                    self.sessions[peer] = keys
                    self.pending_responder.pop(peer, None)
                print(f"\n[HANDSHAKE OK] Đã xác thực {peer}; khóa phiên phía gửi/nhận đã tạo.\n> ", end="", flush=True)
        except (handshake.HandshakeError, ValueError, KeyError) as exc:
            with self.state_lock:
                self.pending_initiator.pop(peer, None)
                self.pending_responder.pop(peer, None)
                self.sessions.pop(peer, None)
            print(f"\n[HANDSHAKE ERROR] Với {peer}: {exc}\n> ", end="", flush=True)

    def send_secure(self, peer, kind, payload):
        with self.state_lock:
            session = self.sessions.get(peer)
        if session is None:
            raise ValueError(f"Chưa có phiên bảo mật với {peer}. Hãy dùng /connect {peer}.")
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        aad = aad_for(session.session_id, self.name, peer, kind)
        nonce, ciphertext = crypto.aes_gcm_encrypt(session.send_key, raw, aad=aad)
        self.send_packet({
            "type": "secure", "from": self.name, "to": peer,
            "session_id": session.session_id, "kind": kind,
            "nonce": nonce.hex(), "ct": base64.b64encode(ciphertext).decode("ascii")
        })

    def handle_secure(self, packet):
        peer = packet.get("from")
        if not isinstance(peer, str):
            return
        with self.state_lock:
            session = self.sessions.get(peer)
        if session is None:
            print(f"\n[SECURITY] Bỏ gói secure từ {peer}: chưa có phiên xác thực.\n> ", end="", flush=True)
            return
        try:
            if packet.get("session_id") != session.session_id:
                raise ValueError("Session ID không khớp.")
            kind = packet["kind"]
            nonce = bytes.fromhex(packet["nonce"])
            ciphertext = base64.b64decode(packet["ct"], validate=True)
            aad = aad_for(session.session_id, peer, self.name, kind)
            plaintext = crypto.aes_gcm_decrypt(session.receive_key, nonce, ciphertext, aad=aad)
            payload = json.loads(plaintext.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("Nội dung giải mã không phải JSON object.")
            if kind == "chat":
                print(f"\n[{peer}] {payload.get('text', '')}\n> ", end="", flush=True)
            elif kind == "file_meta":
                self.start_file(peer, payload)
            elif kind == "file_chunk":
                self.write_chunk(peer, payload)
            elif kind == "file_end":
                self.finish_file(peer, payload)
            else:
                print(f"\n[INFO] Đã xác thực gói loại {kind} từ {peer}.\n> ", end="", flush=True)
        except Exception as exc:
            print(f"\n[SECURITY] Từ chối gói từ {peer}: xác thực/giải mã thất bại ({exc}).\n> ", end="", flush=True)

    def receive_loop(self):
        try:
            while True:
                packet = recv_msg(self.sock)
                kind = packet.get("type")
                if kind == "system":
                    print(f"\n[SYSTEM] {packet.get('msg')}\n> ", end="", flush=True)
                elif kind == "error":
                    print(f"\n[SERVER ERROR] {packet.get('msg')}\n> ", end="", flush=True)
                elif kind in ("HELLO", "HELLO_REPLY", "AUTH"):
                    self.handle_handshake(packet)
                elif kind == "secure":
                    self.handle_secure(packet)
                else:
                    print(f"\n[INFO] Gói không được hỗ trợ: {kind}\n> ", end="", flush=True)
        except (ConnectionError, OSError, ValueError, KeyError) as exc:
            print(f"\n[CLIENT] Mất kết nối: {exc}")

    def send_chat(self, recipient, text):
        self.send_secure(recipient, "chat", {"text": text})

    def send_file(self, recipient, path):
        path = os.path.abspath(os.path.expanduser(path.strip('"')))
        if not os.path.isfile(path):
            raise ValueError("Không tìm thấy tệp.")
        size = validate_file(path)
        file_id = uuid.uuid4().hex
        total = (size + CHUNK_SIZE - 1) // CHUNK_SIZE
        self.send_secure(recipient, "file_meta", {
            "file_id": file_id, "name": os.path.basename(path),
            "size": size, "total": total, "sha256": sha256_file(path)
        })
        with open(path, "rb") as f:
            index = 0
            while True:
                block = f.read(CHUNK_SIZE)
                if not block:
                    break
                self.send_secure(recipient, "file_chunk", {
                    "file_id": file_id, "index": index, "total": total,
                    "data": base64.b64encode(block).decode("ascii")
                })
                index += 1
        self.send_secure(recipient, "file_end", {"file_id": file_id})
        print(f"Đã gửi tệp qua phiên mã hóa: {os.path.basename(path)} ({size} byte).")

    def start_file(self, peer, payload):
        try:
            size = int(payload["size"])
            total = int(payload["total"])
            file_id = str(payload["file_id"])
            name = os.path.basename(str(payload["name"]).replace("\\", "/")) or "download.bin"
            if size < 0 or size > MAX_FILE_SIZE or total < 0:
                raise ValueError("Kích thước tệp không hợp lệ.")
            expected_total = (size + CHUNK_SIZE - 1) // CHUNK_SIZE
            if total != expected_total:
                raise ValueError("Số khối không khớp kích thước.")
            os.makedirs(DOWNLOAD_DIR, exist_ok=True)
            final_path = os.path.join(DOWNLOAD_DIR, name)
            base, ext = os.path.splitext(final_path)
            suffix = 1
            while os.path.exists(final_path) or any(x["path"] == final_path for x in self.incoming_files.values()):
                final_path = f"{base}_{suffix}{ext}"
                suffix += 1
            temp_path = final_path + "." + file_id[:8] + ".part"
            with open(temp_path, "wb"):
                pass
            self.incoming_files[file_id] = {
                "peer": peer, "path": final_path, "temp": temp_path,
                "name": name, "size": size, "total": total, "expected": 0,
                "sha256": str(payload["sha256"]), "digest": hashlib.sha256(), "written": 0
            }
            print(f"\n[FILE] Đang nhận tệp mã hóa {name} từ {peer} ({size} byte).\n> ", end="", flush=True)
        except (KeyError, ValueError, OSError) as exc:
            print(f"\n[FILE ERROR] Metadata bị từ chối: {exc}\n> ", end="", flush=True)

    def write_chunk(self, peer, payload):
        file_id = payload.get("file_id")
        state = self.incoming_files.get(file_id)
        if state is None or state["peer"] != peer:
            return
        try:
            index = int(payload["index"])
            if int(payload["total"]) != state["total"] or index != state["expected"] or index >= state["total"]:
                raise ValueError("Thứ tự hoặc tổng số khối không hợp lệ.")
            block = base64.b64decode(payload["data"], validate=True)
            if state["written"] + len(block) > state["size"]:
                raise ValueError("Dữ liệu vượt kích thước khai báo.")
            with open(state["temp"], "ab") as f:
                f.write(block)
            state["digest"].update(block)
            state["written"] += len(block)
            state["expected"] += 1
        except (ValueError, KeyError, OSError) as exc:
            self.abort_file(file_id, str(exc))

    def finish_file(self, peer, payload):
        file_id = payload.get("file_id")
        state = self.incoming_files.get(file_id)
        if state is None or state["peer"] != peer:
            return
        try:
            actual_hash = state["digest"].hexdigest()
            if state["expected"] != state["total"] or state["written"] != state["size"]:
                raise ValueError("Số khối hoặc kích thước không khớp.")
            if actual_hash != state["sha256"]:
                raise ValueError("SHA-256 không khớp.")
            os.replace(state["temp"], state["path"])
            print(f"\n[FILE OK] Đã lưu {state['path']} | SHA-256={actual_hash}\n> ", end="", flush=True)
            del self.incoming_files[file_id]
        except (ValueError, OSError) as exc:
            self.abort_file(file_id, str(exc))

    def abort_file(self, file_id, reason):
        state = self.incoming_files.pop(file_id, None)
        if state:
            try:
                if os.path.exists(state["temp"]):
                    os.remove(state["temp"])
            except OSError:
                pass
        print(f"\n[FILE ERROR] {reason}\n> ", end="", flush=True)

    def run(self):
        print("Lệnh: /connect TEN | /msg TEN tin_nhắn | /file TEN đường_dẫn_tệp | /sessions | /quit")
        try:
            while True:
                command = input("> ").strip()
                if command == "/quit":
                    break
                elif command.startswith("/connect "):
                    peer = command.split(maxsplit=1)[1].strip()
                    self.connect_peer(peer)
                elif command == "/sessions":
                    with self.state_lock:
                        peers = list(self.sessions.keys())
                    print("Phiên bảo mật đã thiết lập với: " + (", ".join(peers) if peers else "(chưa có)"))
                elif command.startswith("/msg "):
                    parts = command.split(" ", 2)
                    if len(parts) < 3 or not parts[2]:
                        print("Cú pháp: /msg TEN tin_nhắn")
                        continue
                    try:
                        self.send_chat(parts[1], parts[2])
                    except (ValueError, OSError) as exc:
                        print(f"Lỗi gửi tin: {exc}")
                elif command.startswith("/file "):
                    parts = command.split(" ", 2)
                    if len(parts) < 3:
                        print("Cú pháp: /file TEN đường_dẫn_tệp")
                        continue
                    try:
                        self.send_file(parts[1], parts[2])
                    except (ValueError, OSError) as exc:
                        print(f"Lỗi gửi tệp: {exc}")
                elif command:
                    print("Lệnh không hợp lệ. Dùng /connect, /msg, /file, /sessions hoặc /quit.")
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()

def main():
    name = input("Tên của bạn: ").strip()
    if not name:
        print("Tên không được để trống.")
        return
    try:
        ChatClient(name).run()
    except (ConnectionRefusedError, OSError, RuntimeError, ValueError) as exc:
        print(f"[CLIENT ERROR] {exc}")

if __name__ == "__main__":
    main()
