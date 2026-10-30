# import base64
# import hashlib
# import os
# import socket
# import sys
# import threading
# import uuid

# from config import HOST, PORT, CHUNK_SIZE, MAX_FILE_SIZE, DOWNLOAD_DIR
# from protocol import send_msg, recv_msg
# from file_transfer import sha256_file, validate_file

# # FakeSession chỉ là placeholder để kiểm tra networking.
# # Nó KHÔNG mã hóa. Thay bằng session thật do thành viên A cung cấp trước khi demo bảo mật.
# class FakeSession:
#     def encrypt(self, plaintext: bytes, aad: bytes = b""):
#         return 0, plaintext
#     def decrypt(self, counter: int, ciphertext: bytes, aad: bytes = b""):
#         return ciphertext

# class ChatClient:
#     def __init__(self, name):
#         self.name = name
#         self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         self.sock.connect((HOST, PORT))
#         self.send_lock = threading.Lock()
#         self.session = FakeSession()
#         self.incoming_files = {}
#         send_msg(self.sock, {"type": "register", "name": name})
#         self.receiver = threading.Thread(target=self.receive_loop, daemon=True)
#         self.receiver.start()

#     def send_packet(self, packet):
#         # Đảm bảo nhiều thao tác gửi không xen kẽ bytes trên cùng socket.
#         with self.send_lock:
#             send_msg(self.sock, packet)

#     def receive_loop(self):
#         try:
#             while True:
#                 packet = recv_msg(self.sock)
#                 kind = packet.get("type")
#                 if kind == "system":
#                     print(f"\n[SYSTEM] {packet.get('msg')}\n> ", end="", flush=True)
#                 elif kind == "error":
#                     print(f"\n[ERROR] {packet.get('msg')}\n> ", end="", flush=True)
#                 elif kind == "chat":
#                     raw = base64.b64decode(packet["ct"])
#                     text = self.session.decrypt(packet.get("counter", 0), raw, b"chat")
#                     print(f"\n[{packet.get('from')}] {text.decode('utf-8', errors='replace')}\n> ", end="", flush=True)
#                 elif kind == "file_meta":
#                     self.start_file(packet)
#                 elif kind == "file_chunk":
#                     self.write_chunk(packet)
#                 elif kind == "file_end":
#                     self.finish_file(packet)
#                 else:
#                     print(f"\n[INFO] Gói {kind}: {packet}\n> ", end="", flush=True)
#         except (ConnectionError, OSError, ValueError, KeyError) as exc:
#             print(f"\n[CLIENT] Mất kết nối: {exc}")

#     def send_chat(self, recipient, text):
#         counter, ciphertext = self.session.encrypt(text.encode("utf-8"), b"chat")
#         self.send_packet({
#             "type": "chat", "from": self.name, "to": recipient,
#             "counter": counter, "ct": base64.b64encode(ciphertext).decode("ascii")
#         })

#     def send_file(self, recipient, path):
#         path = os.path.abspath(os.path.expanduser(path))
#         if not os.path.isfile(path):
#             print("Không tìm thấy tệp.")
#             return
#         size = validate_file(path)
#         file_id = uuid.uuid4().hex
#         total = (size + CHUNK_SIZE - 1) // CHUNK_SIZE
#         digest = sha256_file(path)
#         self.send_packet({
#             "type": "file_meta", "from": self.name, "to": recipient,
#             "file_id": file_id, "name": os.path.basename(path),
#             "size": size, "total": total, "sha256": digest
#         })
#         with open(path, "rb") as f:
#             index = 0
#             while True:
#                 block = f.read(CHUNK_SIZE)
#                 if not block:
#                     break
#                 aad = f"{file_id}:{index}:{total}".encode()
#                 counter, ciphertext = self.session.encrypt(block, aad)
#                 self.send_packet({
#                     "type": "file_chunk", "from": self.name, "to": recipient,
#                     "file_id": file_id, "index": index, "counter": counter,
#                     "ct": base64.b64encode(ciphertext).decode("ascii")
#                 })
#                 index += 1
#         self.send_packet({
#             "type": "file_end", "from": self.name, "to": recipient,
#             "file_id": file_id
#         })
#         print(f"Đã gửi yêu cầu truyền tệp {os.path.basename(path)} ({size} byte).")

#     def start_file(self, packet):
#         try:
#             size = int(packet["size"])
#             total = int(packet["total"])
#             file_id = packet["file_id"]
#             name = os.path.basename(str(packet["name"]).replace("\\", "/")) or "download.bin"
#             if size < 0 or size > MAX_FILE_SIZE or total < 0:
#                 raise ValueError("Kích thước tệp không hợp lệ.")
#             os.makedirs(DOWNLOAD_DIR, exist_ok=True)
#             final_path = os.path.join(DOWNLOAD_DIR, name)
#             base, ext = os.path.splitext(final_path)
#             suffix = 1
#             while os.path.exists(final_path) or any(x["path"] == final_path for x in self.incoming_files.values()):
#                 final_path = f"{base}_{suffix}{ext}"
#                 suffix += 1
#             temp_path = final_path + ".part"
#             self.incoming_files[file_id] = {
#                 "path": final_path, "temp": temp_path, "name": name,
#                 "size": size, "total": total, "expected": 0,
#                 "sha256": packet["sha256"], "digest": hashlib.sha256(), "written": 0
#             }
#             with open(temp_path, "wb"):
#                 pass
#             print(f"\n[FILE] Đang nhận {name} từ {packet.get('from')} ({size} byte).\n> ", end="", flush=True)
#         except (KeyError, ValueError, OSError) as exc:
#             print(f"\n[FILE ERROR] Metadata không hợp lệ: {exc}\n> ", end="", flush=True)

#     def write_chunk(self, packet):
#         file_id = packet.get("file_id")
#         state = self.incoming_files.get(file_id)
#         if state is None:
#             return
#         try:
#             index = int(packet["index"])
#             if index != state["expected"] or index >= state["total"]:
#                 raise ValueError("Thứ tự khối không hợp lệ.")
#             aad = f"{file_id}:{index}:{state['total']}".encode()
#             ciphertext = base64.b64decode(packet["ct"], validate=True)
#             block = self.session.decrypt(int(packet.get("counter", 0)), ciphertext, aad)
#             if state["written"] + len(block) > state["size"]:
#                 raise ValueError("Dữ liệu nhận vượt kích thước khai báo.")
#             with open(state["temp"], "ab") as f:
#                 f.write(block)
#             state["digest"].update(block)
#             state["written"] += len(block)
#             state["expected"] += 1
#         except (ValueError, KeyError, OSError) as exc:
#             self.abort_file(file_id, f"Lỗi khi nhận khối: {exc}")

#     def finish_file(self, packet):
#         file_id = packet.get("file_id")
#         state = self.incoming_files.get(file_id)
#         if state is None:
#             return
#         try:
#             actual_hash = state["digest"].hexdigest()
#             if state["expected"] != state["total"] or state["written"] != state["size"]:
#                 raise ValueError("Số khối hoặc kích thước không khớp.")
#             if actual_hash != state["sha256"]:
#                 raise ValueError("SHA-256 không khớp.")
#             os.replace(state["temp"], state["path"])
#             print(f"\n[FILE OK] Đã lưu {state['path']} | SHA-256={actual_hash}\n> ", end="", flush=True)
#             del self.incoming_files[file_id]
#         except (ValueError, OSError) as exc:
#             self.abort_file(file_id, str(exc))

#     def abort_file(self, file_id, reason):
#         state = self.incoming_files.pop(file_id, None)
#         if state:
#             try:
#                 if os.path.exists(state["temp"]):
#                     os.remove(state["temp"])
#             except OSError:
#                 pass
#         print(f"\n[FILE ERROR] {reason}\n> ", end="", flush=True)

#     def run(self):
#         print("Lệnh: /msg TEN tin nhắn | /file TEN đường_dẫn_tệp | /quit")
#         try:
#             while True:
#                 command = input("> ").strip()
#                 if command == "/quit":
#                     break
#                 if command.startswith("/msg "):
#                     parts = command.split(" ", 2)
#                     if len(parts) < 3 or not parts[2]:
#                         print("Cú pháp: /msg TEN tin nhắn")
#                         continue
#                     self.send_chat(parts[1], parts[2])
#                 elif command.startswith("/file "):
#                     parts = command.split(" ", 2)
#                     if len(parts) < 3:
#                         print("Cú pháp: /file TEN đường_dẫn_tệp")
#                         continue
#                     try:
#                         self.send_file(parts[1], parts[2].strip('"'))
#                     except (OSError, ValueError) as exc:
#                         print(f"Lỗi gửi tệp: {exc}")
#                 elif command:
#                     print("Lệnh không hợp lệ. Dùng /msg, /file hoặc /quit.")
#         except (KeyboardInterrupt, EOFError):
#             pass
#         finally:
#             try:
#                 self.sock.shutdown(socket.SHUT_RDWR)
#             except OSError:
#                 pass
#             self.sock.close()

# def main():
#     name = input("Tên của bạn: ").strip()
#     if not name:
#         print("Tên không được để trống.")
#         return
#     try:
#         ChatClient(name).run()
#     except (ConnectionRefusedError, OSError) as exc:
#         print(f"Không kết nối được server: {exc}")

# if __name__ == "__main__":
#     main()
import argparse
import base64
import hashlib
import os
import socket
import threading
import uuid

from config import (
    HOST, PORT, CHUNK_SIZE, MAX_FILE_SIZE, DOWNLOAD_DIR,
    KEYS_DIR, MSSVS, HANDSHAKE_TIMEOUT,
)
from protocol import send_msg, recv_msg
from file_transfer import sha256_file, validate_file
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from handshake import Initiator, Responder, HandshakeError
from secure_session import SecureSession


# --------------------------------------------------------------------------- #
# FakeSession — chỉ dùng khi demo "trước khi có crypto"
# --------------------------------------------------------------------------- #
class FakeSession:
    """Không mã hóa. Dùng cho --no-crypto để so sánh."""
    def encrypt(self, plaintext: bytes, aad: bytes = b""):
        return "00" * 12, plaintext
    def decrypt(self, nonce_hex, ciphertext: bytes, aad: bytes = b""):
        return ciphertext
    def make_confirmation(self):
        return b""
    def verify_confirmation(self, blob):
        pass


# --------------------------------------------------------------------------- #
# Load khóa danh tính
# --------------------------------------------------------------------------- #
def load_identity(name: str) -> Ed25519PrivateKey:
    path = os.path.join(KEYS_DIR, f"{name}.priv")
    if not os.path.isfile(path):
        raise SystemExit(
            f"[FATAL] Không thấy khóa định danh {path}.\n"
            f"       Chạy: python generate_keys.py {name} <các tên khác>"
        )
    with open(path, "rb") as f:
        return Ed25519PrivateKey.from_private_bytes(f.read())


def load_peer_pub(name: str, peer: str) -> bytes:
    path = os.path.join(KEYS_DIR, f"{peer}.pub")
    if not os.path.isfile(path):
        raise SystemExit(
            f"[FATAL] Chưa có khóa công khai 'pinned' của {peer}: {path}\n"
            f"       Phải có để handshake xác thực; không có = từ chối."
        )
    with open(path, "rb") as f:
        return f.read()


# --------------------------------------------------------------------------- #
# Trạng thái per-peer
# --------------------------------------------------------------------------- #
class PeerState:
    def __init__(self, name: str):
        self.name = name
        self.session = None
        self.initiator = None
        self.responder = None
        self.ready = threading.Event()
        self.error = None


# --------------------------------------------------------------------------- #
# ChatClient
# --------------------------------------------------------------------------- #
class ChatClient:
    def __init__(self, name, host=HOST, port=PORT, use_crypto=True):
        self.name = name
        self.host = host
        self.port = port
        self.use_crypto = use_crypto
        self.peer_states: dict[str, PeerState] = {}
        self.peers_lock = threading.Lock()
        self.incoming_files = {}

        if use_crypto:
            self.identity_priv = load_identity(name)
        else:
            self.identity_priv = None

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.send_lock = threading.Lock()
        send_msg(self.sock, {"type": "register", "name": name})
        self.receiver = threading.Thread(target=self.receive_loop, daemon=True)
        self.receiver.start()

    # -------------------- helpers --------------------
    def _get_peer_state(self, peer: str) -> PeerState:
        with self.peers_lock:
            if peer not in self.peer_states:
                self.peer_states[peer] = PeerState(peer)
            return self.peer_states[peer]

    # def _require_session(self, peer: str):
    #     state = self._get_peer_state(peer)
    #     if state.session is None:
    #         raise RuntimeError(f"Chưa có session với {peer}")
    #     return state.session
    def _require_session(self, peer: str):
        # Nếu không dùng crypto, lúc nào cũng có FakeSession
        if not self.use_crypto:
            return FakeSession()
            
        state = self._get_peer_state(peer)
        if state.session is None:
            raise RuntimeError(f"Chưa có session với {peer}")
        return state.session

    def send_packet(self, packet: dict) -> None:
        with self.send_lock:
            send_msg(self.sock, packet)

    # -------------------- handshake --------------------
    # def ensure_session(self, peer: str):
    #     if not self.use_crypto:
    #         return FakeSession()
    #     if peer == self.name:
    #         raise ValueError("Không thể nhắn chính mình")
    #     state = self._get_peer_state(peer)
    #     if state.session is not None:
    #         return state.session
    #     if not self.use_crypto:
    #         state.session = FakeSession()
    #         return state.session

    #     if state.initiator is None and state.responder is None:
    #         try:
    #             peer_pub = load_peer_pub(self.name, peer)
    #             state.initiator = Initiator(self.identity_priv, peer_pub, MSSVS)
    #             ch = state.initiator.start()
    #         except Exception as e:
    #             state.error = str(e)
    #             state.ready.set()
    #             raise RuntimeError(f"Không khởi tạo được handshake: {e}") from e

    #         self.send_packet({
    #             "type": "hs_hello", "from": self.name, "to": peer,
    #             "hello": base64.b64encode(ch).decode("ascii"),
    #             "confirm": None,
    #         })

    #     if not state.ready.wait(HANDSHAKE_TIMEOUT):
    #         raise RuntimeError(f"Handshake với {peer} quá thời gian ({HANDSHAKE_TIMEOUT}s)")
    #     if state.error:
    #         raise RuntimeError(f"Handshake với {peer} thất bại: {state.error}")
    #     if state.session is None:
    #         raise RuntimeError(f"Handshake với {peer} không hoàn tất")
    #     return state.session
    def ensure_session(self, peer: str):
        if peer == self.name:
            raise ValueError("Không thể nhắn chính mình")
        
        state = self._get_peer_state(peer)
        
        # 1. Nếu đã có session rồi thì trả về luôn
        if state.session is not None:
            return state.session

        # 2. Nếu đang ở chế độ KHÔNG mã hóa (FakeSession)
        if not self.use_crypto:
            state.session = FakeSession()  # Phải lưu vào state để người nhận dùng
            return state.session

        # 3. Nếu là chế độ BẢO MẬT, chạy Handshake
        if state.initiator is None and state.responder is None:
            try:
                peer_pub = load_peer_pub(self.name, peer)
                state.initiator = Initiator(self.identity_priv, peer_pub, MSSVS)
                ch = state.initiator.start()
            except Exception as e:
                state.error = str(e)
                state.ready.set()
                raise RuntimeError(f"Không khởi tạo được handshake: {e}") from e

            self.send_packet({
                "type": "hs_hello", "from": self.name, "to": peer,
                "hello": base64.b64encode(ch).decode("ascii"),
                "confirm": None,
            })

        if not state.ready.wait(HANDSHAKE_TIMEOUT):
            raise RuntimeError(f"Handshake với {peer} quá thời gian ({HANDSHAKE_TIMEOUT}s)")
        if state.error:
            raise RuntimeError(f"Handshake với {peer} thất bại: {state.error}")
        if state.session is None:
            raise RuntimeError(f"Handshake với {peer} không hoàn tất")
        return state.session

    def handle_hs_hello(self, packet: dict) -> None:
        peer = packet["from"]
        hello_bytes = base64.b64decode(packet["hello"])
        confirm_b64 = packet.get("confirm")
        state = self._get_peer_state(peer)

        if state.session is not None:
            return  # đã có session; bỏ qua bản trùng

        if state.initiator is None:
            # --- Ta là responder ---
            try:
                peer_pub = load_peer_pub(self.name, peer)
                responder = Responder(self.identity_priv, peer_pub, MSSVS)
                sh_bytes, keys = responder.respond(hello_bytes)
            except (HandshakeError, Exception) as e:
                state.error = str(e)
                state.ready.set()
                self.send_packet({"type": "hs_error", "from": self.name,
                                  "to": peer, "reason": str(e)})
                print(f"\n[HANDSHAKE] Từ chối {peer}: {e}\n> ", end="", flush=True)
                return
            state.responder = responder
            state.session = SecureSession(keys)
            our_confirm = keys.make_confirmation()
            self.send_packet({
                "type": "hs_hello", "from": self.name, "to": peer,
                "hello": base64.b64encode(sh_bytes).decode("ascii"),
                "confirm": base64.b64encode(our_confirm).decode("ascii"),
            })
        else:
            # --- Ta là initiator; hoàn tất handshake ---
            try:
                keys = state.initiator.finish(hello_bytes)
            except Exception as e:
                state.error = str(e)
                state.ready.set()
                print(f"\n[HANDSHAKE] Từ chối {peer}: {e}\n> ", end="", flush=True)
                return
            if not confirm_b64:
                state.error = "Responder không gửi kèm confirm"
                state.ready.set()
                return
            try:
                keys.verify_confirmation(base64.b64decode(confirm_b64))
            except Exception as e:
                state.error = f"Confirm của {peer} không hợp lệ: {e}"
                state.ready.set()
                print(f"\n[HANDSHAKE] {state.error}\n> ", end="", flush=True)
                return
            state.session = SecureSession(keys)
            self.send_packet({
                "type": "hs_confirm", "from": self.name, "to": peer,
                "blob": base64.b64encode(keys.make_confirmation()).decode("ascii"),
            })
            state.ready.set()

    def handle_hs_confirm(self, packet: dict) -> None:
        peer = packet["from"]
        state = self._get_peer_state(peer)
        if state.session is None:
            return
        try:
            state.session.verify_confirmation(base64.b64decode(packet["blob"]))
            state.ready.set()
        except Exception as e:
            state.error = str(e)
            state.ready.set()

    def handle_hs_error(self, packet: dict) -> None:
        peer = packet["from"]
        state = self._get_peer_state(peer)
        state.error = f"Peer báo lỗi: {packet.get('reason')}"
        state.ready.set()

    # -------------------- receive --------------------
    def receive_loop(self) -> None:
        try:
            while True:
                packet = recv_msg(self.sock)
                kind = packet.get("type")
                if packet.get("to") and packet["to"] != self.name:
                    continue  # không phải cho mình

                if kind == "system":
                    print(f"\n[SYSTEM] {packet.get('msg')}\n> ", end="", flush=True)
                elif kind == "error":
                    print(f"\n[ERROR] {packet.get('msg')}\n> ", end="", flush=True)
                elif kind == "hs_hello":
                    self.handle_hs_hello(packet)
                elif kind == "hs_confirm":
                    self.handle_hs_confirm(packet)
                elif kind == "hs_error":
                    self.handle_hs_error(packet)
                elif kind == "chat":
                    try:
                        session = self._require_session(packet["from"])
                        raw = base64.b64decode(packet["ct"])
                        text = session.decrypt(packet["nonce"], raw, b"chat")
                        print(f"\n[{packet['from']}] "
                              f"{text.decode('utf-8', errors='replace')}\n> ",
                              end="", flush=True)
                    except Exception as e:
                        print(f"\n[CHAT ERROR] {e}\n> ", end="", flush=True)
                elif kind == "file_meta":
                    self.start_file(packet)
                elif kind == "file_chunk":
                    self.write_chunk(packet)
                elif kind == "file_end":
                    self.finish_file(packet)
                else:
                    print(f"\n[INFO] Gói {kind}\n> ", end="", flush=True)
        except (ConnectionError, OSError, ValueError) as exc:
            print(f"\n[CLIENT] Mất kết nối: {exc}")

    # -------------------- send chat --------------------
    def send_chat(self, recipient: str, text: str) -> None:
        try:
            session = self.ensure_session(recipient)
        except (RuntimeError, ValueError) as e:
            print(f"[HANDSHAKE] {e}")
            return
        nonce_hex, ciphertext = session.encrypt(text.encode("utf-8"), b"chat")
        self.send_packet({
            "type": "chat", "from": self.name, "to": recipient,
            "nonce": nonce_hex,
            "ct": base64.b64encode(ciphertext).decode("ascii"),
        })

    # -------------------- file transfer --------------------
    def send_file(self, recipient: str, path: str) -> None:
        path = os.path.abspath(os.path.expanduser(path))
        if not os.path.isfile(path):
            print("Không tìm thấy tệp.")
            return
        try:
            session = self.ensure_session(recipient)
        except (RuntimeError, ValueError) as e:
            print(f"[HANDSHAKE] {e}")
            return

        size = validate_file(path)
        file_id = uuid.uuid4().hex
        total = (size + CHUNK_SIZE - 1) // CHUNK_SIZE
        digest = sha256_file(path)
        self.send_packet({
            "type": "file_meta", "from": self.name, "to": recipient,
            "file_id": file_id, "name": os.path.basename(path),
            "size": size, "total": total, "sha256": digest,
        })
        with open(path, "rb") as f:
            index = 0
            while True:
                block = f.read(CHUNK_SIZE)
                if not block:
                    break
                aad = f"{file_id}:{index}:{total}".encode()
                nonce_hex, ciphertext = session.encrypt(block, aad)
                self.send_packet({
                    "type": "file_chunk", "from": self.name, "to": recipient,
                    "file_id": file_id, "index": index, "nonce": nonce_hex,
                    "ct": base64.b64encode(ciphertext).decode("ascii"),
                })
                index += 1
        self.send_packet({"type": "file_end", "from": self.name,
                          "to": recipient, "file_id": file_id})
        print(f"Đã gửi {os.path.basename(path)} ({size} byte).")

    def start_file(self, packet: dict) -> None:
        try:
            size = int(packet["size"])
            total = int(packet["total"])
            file_id = packet["file_id"]
            name = os.path.basename(str(packet["name"]).replace("\\", "/")) or "download.bin"
            if size < 0 or size > MAX_FILE_SIZE or total < 0:
                raise ValueError("Kích thước tệp không hợp lệ.")
            os.makedirs(DOWNLOAD_DIR, exist_ok=True)
            final_path = os.path.join(DOWNLOAD_DIR, name)
            base, ext = os.path.splitext(final_path)
            suffix = 1
            while os.path.exists(final_path) or any(
                x["path"] == final_path for x in self.incoming_files.values()
            ):
                final_path = f"{base}_{suffix}{ext}"
                suffix += 1
            temp_path = final_path + ".part"
            self.incoming_files[file_id] = {
                "path": final_path, "temp": temp_path, "name": name,
                "size": size, "total": total, "expected": 0,
                "sha256": packet["sha256"], "digest": hashlib.sha256(),
                "written": 0, "from": packet.get("from"),
            }
            open(temp_path, "wb").close()
            print(f"\n[FILE] Đang nhận {name} từ {packet.get('from')} "
                  f"({size} byte).\n> ", end="", flush=True)
        except (KeyError, ValueError, OSError) as exc:
            print(f"\n[FILE ERROR] Metadata không hợp lệ: {exc}\n> ", end="", flush=True)

    def write_chunk(self, packet: dict) -> None:
        file_id = packet.get("file_id")
        state = self.incoming_files.get(file_id)
        if state is None:
            return
        try:
            session = self._require_session(packet["from"])
        except Exception as e:
            self.abort_file(file_id, str(e))
            return
        try:
            index = int(packet["index"])
            if index != state["expected"] or index >= state["total"]:
                raise ValueError("Thứ tự khối không hợp lệ.")
            aad = f"{file_id}:{index}:{state['total']}".encode()
            ciphertext = base64.b64decode(packet["ct"], validate=True)
            block = session.decrypt(packet["nonce"], ciphertext, aad)
            if state["written"] + len(block) > state["size"]:
                raise ValueError("Dữ liệu vượt kích thước khai báo.")
            with open(state["temp"], "ab") as f:
                f.write(block)
            state["digest"].update(block)
            state["written"] += len(block)
            state["expected"] += 1
        except Exception as exc:
            self.abort_file(file_id, f"Lỗi khối: {exc}")

    def finish_file(self, packet: dict) -> None:
        file_id = packet.get("file_id")
        state = self.incoming_files.get(file_id)
        if state is None:
            return
        try:
            actual = state["digest"].hexdigest()
            if state["expected"] != state["total"] or state["written"] != state["size"]:
                raise ValueError("Số khối/kích thước không khớp.")
            if actual != state["sha256"]:
                raise ValueError("SHA-256 không khớp.")
            os.replace(state["temp"], state["path"])
            print(f"\n[FILE OK] Đã lưu {state['path']} | SHA-256={actual}\n> ",
                  end="", flush=True)
            del self.incoming_files[file_id]
        except (ValueError, OSError) as exc:
            self.abort_file(file_id, str(exc))

    def abort_file(self, file_id: str, reason: str) -> None:
        state = self.incoming_files.pop(file_id, None)
        if state:
            try:
                if os.path.exists(state["temp"]):
                    os.remove(state["temp"])
            except OSError:
                pass
        print(f"\n[FILE ERROR] {reason}\n> ", end="", flush=True)

    # -------------------- REPL --------------------
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
    parser.add_argument("--no-crypto", action="store_true",
                        help="Dùng FakeSession (không an toàn) để so sánh")
    args = parser.parse_args()

    name = input("Tên của bạn: ").strip()
    if not name:
        print("Tên không được để trống.")
        return
    try:
        ChatClient(name, args.host, args.port,
                   use_crypto=not args.no_crypto).run()
    except (ConnectionRefusedError, OSError) as exc:
        print(f"Không kết nối được server: {exc}")


if __name__ == "__main__":
    main()