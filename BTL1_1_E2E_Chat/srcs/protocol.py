import json
import socket
import struct
from config import MAX_MESSAGE_SIZE

def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise ConnectionError("Đối phương đã đóng kết nối.")
        data.extend(part)
    return bytes(data)

def send_msg(sock: socket.socket, payload: dict) -> None:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_MESSAGE_SIZE:
        raise ValueError(f"Gói tin vượt giới hạn {MAX_MESSAGE_SIZE} byte.")
    sock.sendall(struct.pack("!I", len(raw)) + raw)

def recv_msg(sock: socket.socket) -> dict:
    header = recv_exact(sock, 4)
    size = struct.unpack("!I", header)[0]
    if size <= 0 or size > MAX_MESSAGE_SIZE:
        raise ValueError(f"Kích thước gói tin không hợp lệ: {size}")
    obj = json.loads(recv_exact(sock, size).decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("Gói tin phải là JSON object.")
    return obj
