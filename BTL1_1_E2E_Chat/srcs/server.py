import socket
import threading
from config import HOST, PORT
from protocol import send_msg, recv_msg

clients = {}
clients_lock = threading.Lock()
send_locks = {}

def safe_send(conn, packet):
    with clients_lock:
        lock = send_locks.get(conn)
    if lock is None:
        return
    with lock:
        send_msg(conn, packet)

def remove_client(name, conn):
    with clients_lock:
        if name and clients.get(name) is conn:
            clients.pop(name, None)
            send_locks.pop(conn, None)
            print(f"[SERVER] {name} đã ngắt kết nối.")

def handle_client(conn, address):
    name = None
    try:
        conn.settimeout(300)
        first = recv_msg(conn)
        if first.get("type") != "register":
            send_msg(conn, {"type": "error", "msg": "Gói đầu tiên phải là register."})
            return
        name = str(first.get("name", "")).strip()
        if not name or len(name) > 32:
            send_msg(conn, {"type": "error", "msg": "Tên không hợp lệ (1-32 ký tự)."})
            return
        with clients_lock:
            if name in clients:
                send_msg(conn, {"type": "error", "msg": "Tên này đang được sử dụng."})
                return
            clients[name] = conn
            send_locks[conn] = threading.Lock()
        safe_send(conn, {"type": "system", "msg": f"Đã đăng nhập với tên {name}."})
        print(f"[SERVER] {name} kết nối từ {address[0]}:{address[1]}")
        while True:
            packet = recv_msg(conn)
            if packet.get("type") == "register":
                safe_send(conn, {"type": "error", "msg": "Không được đăng ký lại."})
                continue
            recipient = packet.get("to")
            if not isinstance(recipient, str) or not recipient:
                safe_send(conn, {"type": "error", "msg": "Gói tin thiếu người nhận (to)."})
                continue
            with clients_lock:
                target = clients.get(recipient)
            if target is None:
                safe_send(conn, {"type": "error", "msg": f"Người nhận '{recipient}' không trực tuyến."})
                continue
            # Server chỉ chuyển tiếp; không có khóa phiên và không giải mã secure payload.
            try:
                safe_send(target, packet)
                print(f"[SERVER] relay type={packet.get('type')} from={name} to={recipient}")
            except (OSError, ConnectionError, ValueError):
                safe_send(conn, {"type": "error", "msg": f"Không gửi được tới {recipient}."})
    except (ConnectionError, OSError, ValueError, UnicodeDecodeError) as exc:
        print(f"[SERVER] Kết nối {name or address} kết thúc: {exc}")
    finally:
        remove_client(name, conn)
        try:
            conn.close()
        except OSError:
            pass

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[SERVER] Đang lắng nghe tại {HOST}:{PORT}")
    try:
        while True:
            conn, address = server.accept()
            threading.Thread(target=handle_client, args=(conn, address), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[SERVER] Đang dừng...")
    finally:
        server.close()

if __name__ == "__main__":
    main()
