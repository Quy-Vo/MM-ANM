"""
mitm_server.py — Man-in-the-Middle proxy để demo tấn công.

Thay thế server.py trong kịch bản tấn công; client kết nối vào đây
bằng --port 50001.

Các chế độ:
  --attack none         : relay y hệt, không can thiệp (baseline)
  --attack passive      : log toàn bộ traffic; thử decode plaintext
  --attack tamper-hello : sửa 1 bit trong nonce của hs_hello → chữ ký hỏng
  --attack swap-eph     : thay ephemeral key trong hs_hello → chữ ký hỏng

Chạy song song cùng nội dung demo:
  1. server.py + client --no-crypto → mitm --attack passive đọc được mọi thứ.
  2. server.py + client (mặc định)  → mitm --attack passive chỉ thấy ciphertext.
  3. mitm --attack tamper-hello     → handshake fail ngay (chữ ký không hợp lệ).
  4. mitm --attack swap-eph         → handshake fail ngay.
"""
import argparse
import base64
import socket
import threading

import crypto
from protocol import send_msg, recv_msg


class MitmServer:
    def __init__(self, host, port, attack):
        self.host = host
        self.port = port
        self.attack = attack
        self.clients = {}
        self.send_locks = {}
        self.lock = threading.Lock()
        # Khóa danh tính "của MITM" (chỉ mang tính minh họa chế độ tấn công)
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

    def _log(self, packet):
        kind = packet.get("type")
        frm, to = packet.get("from"), packet.get("to")
        if kind == "chat":
            try:
                raw = base64.b64decode(packet["ct"])
                try:
                    text = raw.decode("utf-8")
                    print(f"[MITM] chat {frm}->{to}  PLAINTEXT = {text!r}")
                except UnicodeDecodeError:
                    print(f"[MITM] chat {frm}->{to}  CIPHERTEXT "
                          f"({len(raw)} bytes) {raw[:16].hex()}...")
            except Exception as e:
                print(f"[MITM] chat decode error: {e}")
        elif kind == "hs_hello":
            has_conf = "with-confirm" if packet.get("confirm") else "no-confirm"
            print(f"[MITM] hs_hello  {frm}->{to}  ({has_conf})")
        elif kind == "hs_confirm":
            print(f"[MITM] hs_confirm {frm}->{to}")
        elif kind == "hs_error":
            print(f"[MITM] hs_error {frm}->{to}  reason={packet.get('reason')}")
        elif kind == "file_meta":
            print(f"[MITM] file_meta {frm}->{to}  name={packet.get('name')} "
                  f"size={packet.get('size')} sha256={packet.get('sha256')}")
        elif kind == "file_chunk":
            try:
                raw = base64.b64decode(packet["ct"])
                try:
                    preview = raw[:60].decode("utf-8")
                    print(f"[MITM] file_chunk idx={packet.get('index')} "
                          f"PLAINTEXT head={preview!r}")
                except UnicodeDecodeError:
                    print(f"[MITM] file_chunk idx={packet.get('index')} "
                          f"ciphertext ({len(raw)} bytes)")
            except Exception:
                pass
        elif kind == "file_end":
            print(f"[MITM] file_end  {frm}->{to}")
        elif kind == "register":
            print(f"[MITM] register  name={packet.get('name')}")

    def _modify(self, packet):
        if self.attack not in ("tamper-hello", "swap-eph"):
            return packet
        if packet.get("type") != "hs_hello":
            return packet
        try:
            hello = bytearray(base64.b64decode(packet["hello"]))
        except Exception:
            return packet

        pkt = dict(packet)
        if self.attack == "tamper-hello":
            hello[34] ^= 0x01  # lật 1 bit trong nonce (byte 34 = đầu nonce)
            print(f"[MITM] ** TAMPERED hello nonce byte của {packet.get('from')} **")
        elif self.attack == "swap-eph":
            _, new_eph = crypto.generate_x25519_keypair()
            hello[2:34] = new_eph  # ghi đè eph_pub (byte 2..33)
            print(f"[MITM] ** REPLACED ephemeral key của {packet.get('from')} **")

        pkt["hello"] = base64.b64encode(bytes(hello)).decode("ascii")
        return pkt

    # ------------------------------------------------------------------ #
    def handle_client(self, conn, addr):
        name = None
        try:
            first = recv_msg(conn)
            if first.get("type") != "register":
                send_msg(conn, {"type": "error", "msg": "Gói đầu phải register."})
                return
            name = str(first.get("name", "")).strip()
            if not name or len(name) > 32:
                send_msg(conn, {"type": "error", "msg": "Tên không hợp lệ."})
                return
            with self.lock:
                if name in self.clients:
                    send_msg(conn, {"type": "error", "msg": "Tên đang được dùng."})
                    return
                self.clients[name] = conn
                self.send_locks[conn] = threading.Lock()
            print(f"[MITM] {name} kết nối (attack={self.attack})")
            self.safe_send(conn, {"type": "system",
                                  "msg": f"Đã đăng nhập với tên {name}."})
            while True:
                packet = recv_msg(conn)
                self._log(packet)
                packet = self._modify(packet)
                to = packet.get("to")
                with self.lock:
                    target = self.clients.get(to)
                if target is None:
                    self.safe_send(conn, {"type": "error",
                                          "msg": f"'{to}' không online."})
                    continue
                self.safe_send(target, packet)
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
        print(f"[MITM] Lắng nghe tại {self.host}:{self.port} (attack={self.attack})")
        try:
            while True:
                conn, addr = srv.accept()
                threading.Thread(target=self.handle_client,
                                 args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[MITM] Dừng.")
        finally:
            srv.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=50001)
    p.add_argument("--attack",
                   choices=["none", "passive", "tamper-hello", "swap-eph"],
                   default="passive")
    a = p.parse_args()
    MitmServer(a.host, a.port, a.attack).start()


if __name__ == "__main__":
    main()