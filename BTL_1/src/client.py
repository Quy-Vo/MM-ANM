"""
client.py — Chat và truyền tệp mã hóa đầu cuối (X25519 + HKDF + AES-256-GCM, xác thực bằng Ed25519 đã pin).

Thay đổi so với bản trước (sửa lỗi bảo mật/độ bền):
- Chống replay: mỗi gói có counter trong AAD (xem secure_session.py).
- file_meta và file_end được mã hóa + xác thực (trước đây tên/kích thước/SHA-256 đi dạng plaintext).
- Không còn SystemExit trong luồng nhận: thiếu khóa pin chỉ làm handshake thất bại.
- Gõ sai tên người nhận không làm thoát chương trình.
- Handshake lỗi/timeout xóa trạng thái, lần gửi sau thử lại từ đầu.
- Hai bên khởi tạo cùng lúc: bên có tên nhỏ hơn (theo thứ tự chữ cái) giữ vai khởi tạo.
- Phiên của bên responder chỉ được kích hoạt SAU khi xác nhận khóa của initiator hợp lệ.
- Bên nhận báo "no_session" khi chưa có phiên (ví dụ sau khi khởi động lại) để bên gửi bắt tay lại.
- Kiểm tra tên đối phương bằng regex trước khi ghép đường dẫn khóa.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import socket
import threading
import uuid

from config import (
    HOST, PORT, CHUNK_SIZE, MAX_FILE_SIZE, DOWNLOAD_DIR,
    KEYS_DIR, MSSVS, HANDSHAKE_TIMEOUT,
)
from protocol import send_msg, recv_msg, valid_name
from file_transfer import sha256_file, validate_file
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import crypto
from handshake import Initiator, Responder, ROLE_INITIATOR, ROLE_RESPONDER
from secure_session import SecureSession

FILE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class FakeSession:
    """Không mã hóa. Chỉ dùng cho --no-crypto để so sánh."""
    def encrypt(self, plaintext: bytes, aad: bytes = b""):
        return "00" * 12, plaintext

    def decrypt(self, hdr, ciphertext: bytes, aad: bytes = b""):
        return ciphertext


class PeerKeyError(ValueError):
    """Thiếu hoặc sai khóa công khai pinned của đối phương."""


def load_identity(name: str) -> Ed25519PrivateKey:
    path = os.path.join(KEYS_DIR, f"{name}.priv") if valid_name(name) else ""
    if not path or not os.path.isfile(path):
        raise SystemExit(
            f"[FATAL] Không thấy khóa định danh cho '{name}' trong {KEYS_DIR}.\n"
            f"       Chạy: python generate_keys.py {name} <các tên khác>"
        )
    with open(path, "rb") as f:
        return Ed25519PrivateKey.from_private_bytes(f.read())


def load_peer_pub(peer: str) -> bytes:
    if not valid_name(peer):
        raise PeerKeyError("Tên đối phương không hợp lệ")
    path = os.path.join(KEYS_DIR, f"{peer}.pub")
    if not os.path.isfile(path):
        raise PeerKeyError(f"Chưa có khóa công khai pinned của {peer}")
    with open(path, "rb") as f:
        data = f.read()
    if len(data) != 32:
        raise PeerKeyError(f"Khóa công khai của {peer} sai độ dài")
    return data


class PeerState:
    def __init__(self, name: str):
        self.name = name
        self.session = None        # phiên đang dùng
        self.initiator = None      # đang chờ ServerHello
        self.pending_keys = None   # responder: đã trả lời, chờ confirm của initiator
        self.ready = threading.Event()
        self.error = None


class ChatClient:
    def __init__(self, name, host=HOST, port=PORT, use_crypto=True):
        if not valid_name(name):
            raise ValueError("Tên chỉ gồm chữ, số, '_' hoặc '-' (1-32 ký tự).")
        self.name = name
        self.host = host
        self.port = port
        self.use_crypto = use_crypto
        self.peer_states: dict[str, PeerState] = {}
        self.peers_lock = threading.RLock()
        self.tx_lock = threading.Lock()   # giữ thứ tự counter == thứ tự gửi
        self.incoming_files = {}
        self.inbox = []        # (peer, text) — phục vụ kiểm thử
        self.files_ok = []     # đường dẫn tệp nhận thành công
        self.identity_priv = load_identity(name) if use_crypto else None

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.send_lock = threading.Lock()
        send_msg(self.sock, {"type": "register", "name": name})
        self.receiver = threading.Thread(target=self.receive_loop, daemon=True)
        self.receiver.start()

    # ------------------------------------------------------------------ #
    def send_packet(self, packet: dict) -> None:
        with self.send_lock:
            send_msg(self.sock, packet)

    def _say(self, text: str) -> None:
        print(f"\n{text}\n> ", end="", flush=True)

    def _active_session(self, peer: str):
        if not self.use_crypto:
            return FakeSession()
        with self.peers_lock:
            state = self.peer_states.get(peer)
            return state.session if state else None

    def _send_error(self, peer: str, reason: str) -> None:
        try:
            self.send_packet({"type": "hs_error", "from": self.name, "to": peer, "reason": reason})
        except OSError:
            pass

    # ------------------------------------------------------------------ #
    # Trạng thái handshake
    # ------------------------------------------------------------------ #
    def _fail(self, state: PeerState, reason: str) -> None:
        """Handshake thất bại: dọn trạng thái chờ, đánh thức luồng đang đợi."""
        with self.peers_lock:
            state.initiator = None
            state.pending_keys = None
            if state.session is None:
                state.error = reason
                if self.peer_states.get(state.name) is state:
                    del self.peer_states[state.name]   # lần sau bắt đầu lại từ đầu
            state.ready.set()

    def _success(self, state: PeerState, keys) -> None:
        with self.peers_lock:
            state.session = SecureSession(keys)
            state.initiator = None
            state.pending_keys = None
            state.error = None
            self.peer_states[state.name] = state
            state.ready.set()
        # Bằng chứng yêu cầu MSSV của đề: Key = SHA256(MSSV_1 || MSSV_2 || ...) là đầu vào của KDF (salt/transcript),
        # KHÔNG phải khóa AES trực tiếp. Khóa phiên thật đến từ X25519 + HKDF.
        self._say(f"[HANDSHAKE] Phiên với {state.name} đã thiết lập. "
                  f"Hello, We are {', '.join(MSSVS)} | SHA256(MSSV)={crypto.hash_mssvs(MSSVS).hex()}")

    def ensure_session(self, peer: str):
        if not valid_name(peer):
            raise ValueError("Tên người nhận không hợp lệ")
        if peer == self.name:
            raise ValueError("Không thể nhắn chính mình")
        if not self.use_crypto:
            return FakeSession()

        with self.peers_lock:
            state = self.peer_states.get(peer)
            if state is not None and state.session is not None:
                return state.session
            if state is None:
                state = PeerState(peer)
                try:
                    initiator = Initiator(self.identity_priv, load_peer_pub(peer), MSSVS)
                    hello = initiator.start()
                except Exception as exc:
                    raise RuntimeError(f"Không khởi tạo được handshake: {exc}") from exc
                state.initiator = initiator
                self.peer_states[peer] = state
                self.send_packet({
                    "type": "hs_hello", "from": self.name, "to": peer,
                    "hello": base64.b64encode(hello).decode("ascii"), "confirm": None,
                })

        if not state.ready.wait(HANDSHAKE_TIMEOUT):
            self._fail(state, "timeout")
            raise RuntimeError(f"Handshake với {peer} quá thời gian ({HANDSHAKE_TIMEOUT}s)")
        if state.session is None:
            raise RuntimeError(f"Handshake với {peer} thất bại: {state.error or 'không hoàn tất'}")
        return state.session

    def handle_hs_hello(self, packet: dict) -> None:
        if not self.use_crypto:
            return
        peer = packet.get("from")
        if not valid_name(peer) or peer == self.name:
            return
        try:
            hello_bytes = base64.b64decode(packet["hello"], validate=True)
        except (KeyError, ValueError, TypeError):
            return
        if len(hello_bytes) < 2:
            return
        role = hello_bytes[1]
        if role == ROLE_INITIATOR:
            self._respond_to_initiator(peer, hello_bytes)
        elif role == ROLE_RESPONDER:
            self._complete_as_initiator(peer, hello_bytes, packet.get("confirm"))

    def _respond_to_initiator(self, peer: str, hello_bytes: bytes) -> None:
        with self.peers_lock:
            state = self.peer_states.get(peer)
            if state is None:
                state = PeerState(peer)
                self.peer_states[peer] = state
            if state.initiator is not None:
                if self.name < peer:
                    return            # ta giữ vai khởi tạo, bỏ qua hello của đối phương
                state.initiator = None  # ta nhường: chuyển sang vai responder, giữ nguyên người đang chờ
            try:
                responder = Responder(self.identity_priv, load_peer_pub(peer), MSSVS)
                server_hello, keys = responder.respond(hello_bytes)
            except Exception as exc:
                self._fail(state, str(exc))
                self._send_error(peer, str(exc))
                self._say(f"[HANDSHAKE] Từ chối {peer}: {exc}")
                return
            state.pending_keys = keys   # CHƯA kích hoạt phiên cho tới khi xác nhận của initiator hợp lệ
            self.send_packet({
                "type": "hs_hello", "from": self.name, "to": peer,
                "hello": base64.b64encode(server_hello).decode("ascii"),
                "confirm": base64.b64encode(keys.make_confirmation()).decode("ascii"),
            })

    def _complete_as_initiator(self, peer: str, hello_bytes: bytes, confirm_b64) -> None:
        with self.peers_lock:
            state = self.peer_states.get(peer)
            if state is None or state.initiator is None:
                return                  # ServerHello lạc/phát lại: bỏ qua
            initiator = state.initiator
            state.initiator = None      # mỗi Initiator chỉ dùng một lần
        try:
            keys = initiator.finish(hello_bytes)
            if not confirm_b64:
                raise ValueError("Responder không gửi kèm confirm")
            keys.verify_confirmation(base64.b64decode(confirm_b64, validate=True))
        except Exception as exc:
            self._fail(state, str(exc))
            self._say(f"[HANDSHAKE] Từ chối {peer}: {exc}")
            return
        self.send_packet({
            "type": "hs_confirm", "from": self.name, "to": peer,
            "blob": base64.b64encode(keys.make_confirmation()).decode("ascii"),
        })
        self._success(state, keys)

    def handle_hs_confirm(self, packet: dict) -> None:
        peer = packet.get("from")
        if not self.use_crypto or not valid_name(peer):
            return
        with self.peers_lock:
            state = self.peer_states.get(peer)
            if state is None or state.pending_keys is None:
                return
            keys = state.pending_keys
        try:
            keys.verify_confirmation(base64.b64decode(packet["blob"], validate=True))
        except Exception as exc:
            self._fail(state, f"Confirm của {peer} không hợp lệ: {exc}")
            self._say(f"[HANDSHAKE] Confirm của {peer} không hợp lệ: {exc}")
            return
        self._success(state, keys)

    def handle_hs_error(self, packet: dict) -> None:
        peer = packet.get("from")
        if not self.use_crypto or not valid_name(peer):
            return
        reason = str(packet.get("reason"))[:200]
        with self.peers_lock:
            state = self.peer_states.get(peer)
            if state is None:
                return
            if reason == "no_session":
                # Bên kia mất phiên (ví dụ khởi động lại): bỏ phiên cũ, lần gửi sau bắt tay lại.
                if state.session is not None and state.initiator is None and state.pending_keys is None:
                    del self.peer_states[peer]
                    self._say(f"[SESSION] {peer} không còn phiên; gửi lại để bắt tay mới.")
                return
            if state.initiator is not None:
                self._fail(state, f"Peer báo lỗi: {reason}")

    # ------------------------------------------------------------------ #
    # Nhận
    # ------------------------------------------------------------------ #
    def receive_loop(self) -> None:
        try:
            while True:
                packet = recv_msg(self.sock)
                if packet.get("to") and packet["to"] != self.name:
                    continue
                try:
                    self.dispatch(packet)
                except Exception as exc:   # một gói xấu không được làm chết luồng nhận
                    self._say(f"[CLIENT] Bỏ qua gói lỗi ({packet.get('type')}): {exc}")
        except (ConnectionError, OSError, ValueError) as exc:
            print(f"\n[CLIENT] Mất kết nối: {exc}")

    def dispatch(self, packet: dict) -> None:
        kind = packet.get("type")
        if kind == "system":
            self._say(f"[SYSTEM] {packet.get('msg')}")
        elif kind == "error":
            self._say(f"[ERROR] {packet.get('msg')}")
        elif kind == "hs_hello":
            self.handle_hs_hello(packet)
        elif kind == "hs_confirm":
            self.handle_hs_confirm(packet)
        elif kind == "hs_error":
            self.handle_hs_error(packet)
        elif kind == "chat":
            self.handle_chat(packet)
        elif kind == "file_meta":
            self.start_file(packet)
        elif kind == "file_chunk":
            self.write_chunk(packet)
        elif kind == "file_end":
            self.finish_file(packet)
        else:
            self._say(f"[INFO] Gói {kind}")

    def _open(self, packet: dict, session, aad: bytes) -> bytes:
        ciphertext = base64.b64decode(packet["ct"], validate=True)
        return session.decrypt(packet["hdr"], ciphertext, aad)

    def handle_chat(self, packet: dict) -> None:
        peer = packet.get("from")
        if not valid_name(peer):
            return
        session = self._active_session(peer)
        if session is None:
            self._say(f"[CHAT ERROR] Chưa có session với {peer}")
            self._send_error(peer, "no_session")
            return
        try:
            text = self._open(packet, session, b"chat").decode("utf-8", errors="replace")
        except Exception as exc:
            self._say(f"[CHAT ERROR] {exc}")
            return
        self.inbox.append((peer, text))
        self._say(f"[{peer}] {text}")

    # ------------------------------------------------------------------ #
    # Gửi
    # ------------------------------------------------------------------ #
    def _send_secure(self, recipient: str, session, kind: str, plaintext: bytes, aad: bytes, **fields) -> None:
        with self.tx_lock:   # encrypt + gửi liền nhau để counter đi đúng thứ tự
            hdr, ciphertext = session.encrypt(plaintext, aad)
            self.send_packet({
                "type": kind, "from": self.name, "to": recipient,
                "hdr": hdr, "ct": base64.b64encode(ciphertext).decode("ascii"), **fields,
            })

    def send_chat(self, recipient: str, text: str) -> None:
        try:
            session = self.ensure_session(recipient)
        except (RuntimeError, ValueError) as exc:
            print(f"[HANDSHAKE] {exc}")
            return
        self._send_secure(recipient, session, "chat", text.encode("utf-8"), b"chat")

    def send_file(self, recipient: str, path: str) -> None:
        path = os.path.abspath(os.path.expanduser(path))
        if not os.path.isfile(path):
            print("Không tìm thấy tệp.")
            return
        try:
            session = self.ensure_session(recipient)
        except (RuntimeError, ValueError) as exc:
            print(f"[HANDSHAKE] {exc}")
            return

        size = validate_file(path)
        file_id = uuid.uuid4().hex
        total = (size + CHUNK_SIZE - 1) // CHUNK_SIZE
        meta = json.dumps({
            "name": os.path.basename(path), "size": size, "total": total, "sha256": sha256_file(path),
        }, ensure_ascii=False).encode("utf-8")
        self._send_secure(recipient, session, "file_meta", meta, b"file_meta:" + file_id.encode(), file_id=file_id)
        with open(path, "rb") as f:
            index = 0
            while True:
                block = f.read(CHUNK_SIZE)
                if not block:
                    break
                aad = f"{file_id}:{index}:{total}".encode()
                self._send_secure(recipient, session, "file_chunk", block, aad, file_id=file_id, index=index)
                index += 1
        self._send_secure(recipient, session, "file_end", b"end", b"file_end:" + file_id.encode(), file_id=file_id)
        print(f"Đã gửi {os.path.basename(path)} ({size} byte).")

    # ------------------------------------------------------------------ #
    # Nhận tệp
    # ------------------------------------------------------------------ #
    def start_file(self, packet: dict) -> None:
        peer, file_id = packet.get("from"), packet.get("file_id")
        try:
            if not valid_name(peer) or not isinstance(file_id, str) or not FILE_ID_RE.match(file_id):
                raise ValueError("Gói file_meta không hợp lệ")
            session = self._active_session(peer)
            if session is None:
                self._send_error(peer, "no_session")
                raise ValueError(f"Chưa có session với {peer}")
            meta = json.loads(self._open(packet, session, b"file_meta:" + file_id.encode()).decode("utf-8"))
            size, total = int(meta["size"]), int(meta["total"])
            sha = str(meta["sha256"]).lower()
            if size < 0 or size > MAX_FILE_SIZE or total != (size + CHUNK_SIZE - 1) // CHUNK_SIZE:
                raise ValueError("Kích thước tệp không hợp lệ.")
            if not SHA256_RE.match(sha):
                raise ValueError("SHA-256 không hợp lệ.")
            name = os.path.basename(str(meta["name"]).replace("\\", "/"))
            name = "".join(ch for ch in name if ch >= " " and ch != "\x7f")
            if name in ("", ".", ".."):
                name = "download.bin"
            key = (peer, file_id)
            if key in self.incoming_files:
                raise ValueError("file_id đã tồn tại.")
            os.makedirs(DOWNLOAD_DIR, exist_ok=True)
            final_path = os.path.join(DOWNLOAD_DIR, name)
            base, ext = os.path.splitext(final_path)
            suffix = 1
            while os.path.exists(final_path) or any(x["path"] == final_path for x in self.incoming_files.values()):
                final_path = f"{base}_{suffix}{ext}"
                suffix += 1
            if os.path.dirname(os.path.realpath(final_path)) != os.path.realpath(DOWNLOAD_DIR):
                raise ValueError("Tên tệp không an toàn.")
            temp_path = final_path + ".part"
            self.incoming_files[key] = {
                "path": final_path, "temp": temp_path, "name": name, "size": size, "total": total,
                "expected": 0, "sha256": sha, "digest": hashlib.sha256(), "written": 0,
            }
            open(temp_path, "wb").close()
            self._say(f"[FILE] Đang nhận {name} từ {peer} ({size} byte).")
        except Exception as exc:
            self._say(f"[FILE ERROR] Metadata không hợp lệ: {exc}")

    def write_chunk(self, packet: dict) -> None:
        key = (packet.get("from"), packet.get("file_id"))
        state = self.incoming_files.get(key)
        if state is None:
            return
        try:
            session = self._active_session(key[0])
            if session is None:
                raise ValueError("Mất session")
            index = packet["index"]
            if isinstance(index, bool) or not isinstance(index, int):
                raise ValueError("Chỉ số khối không hợp lệ.")
            if index != state["expected"] or index >= state["total"]:
                raise ValueError("Thứ tự khối không hợp lệ.")
            aad = f"{key[1]}:{index}:{state['total']}".encode()
            block = self._open(packet, session, aad)
            if state["written"] + len(block) > state["size"]:
                raise ValueError("Dữ liệu vượt kích thước khai báo.")
            with open(state["temp"], "ab") as f:
                f.write(block)
            state["digest"].update(block)
            state["written"] += len(block)
            state["expected"] += 1
        except Exception as exc:
            self.abort_file(key, f"Lỗi khối: {exc}")

    def finish_file(self, packet: dict) -> None:
        key = (packet.get("from"), packet.get("file_id"))
        state = self.incoming_files.get(key)
        if state is None:
            return
        try:
            session = self._active_session(key[0])
            if session is None:
                raise ValueError("Mất session")
            if self._open(packet, session, b"file_end:" + key[1].encode()) != b"end":
                raise ValueError("Gói kết thúc không đúng.")
            actual = state["digest"].hexdigest()
            if state["expected"] != state["total"] or state["written"] != state["size"]:
                raise ValueError("Số khối/kích thước không khớp.")
            if actual != state["sha256"]:
                raise ValueError("SHA-256 không khớp.")
            os.replace(state["temp"], state["path"])
            del self.incoming_files[key]
            self.files_ok.append(state["path"])
            self._say(f"[FILE OK] Đã lưu {state['path']} | SHA-256={actual}")
        except Exception as exc:
            self.abort_file(key, str(exc))

    def abort_file(self, key, reason: str) -> None:
        state = self.incoming_files.pop(key, None)
        if state:
            try:
                if os.path.exists(state["temp"]):
                    os.remove(state["temp"])
            except OSError:
                pass
        self._say(f"[FILE ERROR] {reason}")

    # ------------------------------------------------------------------ #
    def run(self) -> None:
        mode = "SECURE (Ed25519 + X25519 + AES-GCM)" if self.use_crypto else "FAKE (không mã hóa)"
        print(f"Chế độ: {mode}")
        print("Lệnh: /msg TEN tin nhắn | /file TEN đường_dẫn | /quit")
        try:
            while True:
                command = input("> ").strip()
                if command == "/quit":
                    break
                if command.startswith("/msg "):
                    parts = command.split(" ", 2)
                    if len(parts) < 3 or not parts[2]:
                        print("Cú pháp: /msg TEN tin nhắn")
                        continue
                    self.send_chat(parts[1], parts[2])
                elif command.startswith("/file "):
                    parts = command.split(" ", 2)
                    if len(parts) < 3:
                        print("Cú pháp: /file TEN đường_dẫn")
                        continue
                    try:
                        self.send_file(parts[1], parts[2].strip('"'))
                    except (OSError, ValueError) as exc:
                        print(f"Lỗi gửi tệp: {exc}")
                elif command:
                    print("Lệnh không hợp lệ.")
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--no-crypto", action="store_true", help="Dùng FakeSession (không an toàn) để so sánh")
    args = parser.parse_args()

    name = input("Tên của bạn: ").strip()
    if not valid_name(name):
        print("Tên chỉ gồm chữ, số, '_' hoặc '-' (1-32 ký tự).")
        return
    try:
        ChatClient(name, args.host, args.port, use_crypto=not args.no_crypto).run()
    except (ConnectionRefusedError, OSError) as exc:
        print(f"Không kết nối được server: {exc}")


if __name__ == "__main__":
    main()
