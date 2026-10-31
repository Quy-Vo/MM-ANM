import json
import socket
import struct
from config import MAX_MESSAGE_SIZE

def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise ConnectionError("Peer đã đóng kết nối.")
        data.extend(part)
    return bytes(data)

def send_msg(sock: socket.socket, payload: dict) -> None:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_MESSAGE_SIZE:
        raise ValueError(f"Gói tin vượt giới hạn {MAX_MESSAGE_SIZE} byte.")
    packet = struct.pack("!I", len(raw)) + raw
    sock.sendall(packet)

def recv_msg(sock: socket.socket) -> dict:
    header = recv_exact(sock, 4)
    size = struct.unpack("!I", header)[0]
    if size <= 0 or size > MAX_MESSAGE_SIZE:
        raise ValueError(f"Kích thước gói tin không hợp lệ: {size}")
    raw = recv_exact(sock, size)
    obj = json.loads(raw.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("Gói tin phải là JSON object.")
    return obj


import re

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def valid_name(name) -> bool:
    """Tên người dùng chỉ gồm chữ/số/_/-; dùng cho đăng ký, định tuyến và ghép đường dẫn khóa."""
    return isinstance(name, str) and NAME_RE.match(name) is not None
