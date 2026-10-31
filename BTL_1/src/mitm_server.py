"""
mitm_server.py — Man-in-the-Middle proxy để demo tấn công (đóng vai server trung gian).

Client kết nối vào đây bằng --port 50001. Các chế độ (--attack):
  none          : relay y hệt, không can thiệp (đối chứng)
  passive       : nghe lén, log mọi gói và thử đọc nội dung
  tamper-hello  : lật 1 bit trong nonce của hs_hello  -> chữ ký Ed25519 sai
  swap-eph      : thay khóa X25519 tạm thời trong hs_hello -> chữ ký Ed25519 sai
  impersonate   : MitM thật: tự kết thúc handshake với CẢ HAI bên bằng khóa Ed25519 của kẻ tấn công
                  -> cả hai bên phải từ chối vì khác khóa đã pin
  tamper-ct     : lật 1 bit trong ciphertext của chat / file_meta / file_chunk -> AES-GCM báo lỗi
  replay        : gửi mỗi gói chat/tệp hai lần -> bản thứ hai bị từ chối (counter không tăng)
"""
import argparse
import base64
import os
import socket
import threading

import crypto
from config import KEYS_DIR, MSSVS
from handshake import Hello, Initiator, Responder, ROLE_INITIATOR, ROLE_RESPONDER
from protocol import send_msg, recv_msg, valid_name

ATTACKS = ["none", "passive", "tamper-hello", "swap-eph", "impersonate", "tamper-ct", "replay"]
SECURE_KINDS = ("chat", "file_meta", "file_chunk", "file_end")


def _b64d(s):
    return base64.b64decode(s, validate=True)


def _b64e(b):
    return base64.b64encode(b).decode("ascii")


class MitmServer:
    def __init__(self, host, port, attack):
        self.host, self.port, self.attack = host, port, attack
        self.clients = {}
        self.send_locks = {}
        self.lock = threading.Lock()
        # Khóa danh tính của KẺ TẤN CÔNG (không nằm trong danh sách pin của ai)
        self.mitm_priv, self.mitm_pub = crypto.generate_ed25519_keypair()

    # ------------------------------------------------------------------ #
    def safe_send(self, conn, packet):
        with self.lock:
            lock = self.send_locks.get(conn)
        if lock is None:
            return
        with lock:
            try:
                send_msg(conn, packet)
            except (OSError, ConnectionError) as e:
                print(f"[MITM] send error: {e}")

    def _pub_of(self, name):
        """Khóa công khai là thông tin công khai nên kẻ tấn công đọc được."""
        if not valid_name(name):
            raise ValueError("tên không hợp lệ")
        with open(os.path.join(KEYS_DIR, f"{name}.pub"), "rb") as f:
            return f.read()

    # ------------------------------------------------------------------ #
    def _log(self, packet):
        kind = packet.get("type")
        frm, to = packet.get("from"), packet.get("to")
        if kind in ("chat", "file_meta", "file_end"):
            try:
                raw = _b64d(packet["ct"])
                try:
                    print(f"[MITM] {kind} {frm}->{to}  PLAINTEXT = {raw.decode('utf-8')!r}")
                except UnicodeDecodeError:
                    print(f"[MITM] {kind} {frm}->{to}  CIPHERTEXT ({len(raw)} bytes) {raw[:16].hex()}...")
            except Exception as e:
                print(f"[MITM] {kind} decode error: {e}")
        elif kind == "hs_hello":
            print(f"[MITM] hs_hello  {frm}->{to}  ({'with-confirm' if packet.get('confirm') else 'no-confirm'})")
        elif kind == "hs_confirm":
            print(f"[MITM] hs_confirm {frm}->{to}")
        elif kind == "hs_error":
            print(f"[MITM] hs_error {frm}->{to}  reason={packet.get('reason')}")
        elif kind == "file_chunk":
            try:
                raw = _b64d(packet["ct"])
                try:
                    print(f"[MITM] file_chunk idx={packet.get('index')} PLAINTEXT head={raw[:60].decode('utf-8')!r}")
                except UnicodeDecodeError:
                    print(f"[MITM] file_chunk idx={packet.get('index')} ciphertext ({len(raw)} bytes)")
            except Exception:
                pass
        elif kind == "register":
            print(f"[MITM] register  name={packet.get('name')}")

    # ------------------------------------------------------------------ #
    def _plan(self, sender, packet):
        """Trả về danh sách (tên_người_nhận, gói) sẽ được chuyển đi."""
        to = packet.get("to")
        kind = packet.get("type")
        a = self.attack

        if a in ("tamper-hello", "swap-eph") and kind == "hs_hello":
            try:
                raw = _b64d(packet["hello"])
                h = Hello.from_bytes(raw, raw[1])
                if a == "tamper-hello":
                    nonce = bytearray(h.nonce)
                    nonce[0] ^= 0x01
                    h = Hello(h.role, h.hello_str, h.ephemeral_public, bytes(nonce), h.signature)
                    print(f"[MITM] ** TAMPERED nonce trong hello của {sender} **")
                else:
                    _, new_eph = crypto.generate_x25519_keypair()
                    h = Hello(h.role, h.hello_str, new_eph, h.nonce, h.signature)
                    print(f"[MITM] ** REPLACED ephemeral key trong hello của {sender} **")
                return [(to, dict(packet, hello=_b64e(h.to_bytes())))]
            except Exception as e:
                print(f"[MITM] không sửa được hello: {e}")
                return [(to, packet)]

        if a == "impersonate" and kind in ("hs_hello", "hs_confirm"):
            return self._impersonate(sender, packet)

        if a == "tamper-ct" and kind in ("chat", "file_meta", "file_chunk"):
            try:
                ct = bytearray(_b64d(packet["ct"]))
                ct[0] ^= 0x01
                print(f"[MITM] ** TAMPERED ciphertext {kind} {sender}->{to} **")
                return [(to, dict(packet, ct=_b64e(bytes(ct))))]
            except Exception:
                return [(to, packet)]

        if a == "replay" and kind in SECURE_KINDS:
            print(f"[MITM] ** REPLAY {kind} {sender}->{to} (gửi 2 lần) **")
            return [(to, packet), (to, dict(packet))]

        return [(to, packet)]

    def _impersonate(self, sender, packet):
        """Kẻ tấn công giả làm người nhận với người gửi, và giả làm người gửi với người nhận."""
        to = packet.get("to")
        if packet.get("type") != "hs_hello":
            return []  # không chuyển hs_confirm thật
        try:
            raw = _b64d(packet["hello"])
            if raw[1] != ROLE_INITIATOR:
                return []
            # (1) Trả lời người gửi, giả làm `to`, ký bằng khóa của kẻ tấn công
            responder = Responder(self.mitm_priv, self._pub_of(sender), MSSVS)
            server_hello, keys = responder.respond(raw)
            to_sender = {"type": "hs_hello", "from": to, "to": sender,
                         "hello": _b64e(server_hello), "confirm": _b64e(keys.make_confirmation())}
            # (2) Khởi tạo handshake với người nhận, giả làm `sender`, ký bằng khóa của kẻ tấn công
            initiator = Initiator(self.mitm_priv, self._pub_of(to), MSSVS)
            to_target = {"type": "hs_hello", "from": sender, "to": to,
                         "hello": _b64e(initiator.start()), "confirm": None}
            print(f"[MITM] ** IMPERSONATE: giả làm {to} với {sender} và giả làm {sender} với {to} **")
            return [(sender, to_sender), (to, to_target)]
        except Exception as e:
            print(f"[MITM] impersonate thất bại: {e}")
            return []

    # ------------------------------------------------------------------ #
    def handle_client(self, conn, addr):
        name = None
        try:
            first = recv_msg(conn)
            if first.get("type") != "register":
                send_msg(conn, {"type": "error", "msg": "Gói đầu phải register."})
                return
            name = str(first.get("name", "")).strip()
            if not valid_name(name):
                send_msg(conn, {"type": "error", "msg": "Tên không hợp lệ."})
                return
            with self.lock:
                if name in self.clients:
                    send_msg(conn, {"type": "error", "msg": "Tên đang được dùng."})
                    return
                self.clients[name] = conn
                self.send_locks[conn] = threading.Lock()
            print(f"[MITM] {name} kết nối (attack={self.attack})", flush=True)
            self.safe_send(conn, {"type": "system", "msg": f"Đã đăng nhập với tên {name}."})
            while True:
                packet = recv_msg(conn)
                packet["from"] = name
                if self.attack != "none":
                    self._log(packet)
                for target_name, pkt in self._plan(name, packet):
                    with self.lock:
                        target = self.clients.get(target_name)
                    if target is None:
                        self.safe_send(conn, {"type": "error", "to": to, "msg": f"'{to}' không online."})
                        continue
                    self.safe_send(target, pkt)
        except (ConnectionError, OSError, ValueError) as e:
            print(f"[MITM] {name or addr} ngắt: {e}")
        finally:
            with self.lock:
                if name and self.clients.get(name) is conn:
                    self.clients.pop(name, None)
                    self.send_locks.pop(conn, None)
                    print(f"[MITM] {name} đã đóng.")
            try:
                conn.close()
            except OSError:
                pass

    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen()
        print(f"[MITM] Lắng nghe tại {self.host}:{self.port} (attack={self.attack})", flush=True)
        try:
            while True:
                conn, addr = srv.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[MITM] Dừng.")
        finally:
            srv.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=50001)
    p.add_argument("--attack", choices=ATTACKS, default="passive")
    a = p.parse_args()
    MitmServer(a.host, a.port, a.attack).start()


if __name__ == "__main__":
    main()
