# Các hàm hỗ trợ metadata/hash; luồng gửi/nhận nằm trong client.py để dùng chung socket.
import hashlib
import os
from config import CHUNK_SIZE, MAX_FILE_SIZE

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()

def validate_file(path):
    size = os.path.getsize(path)
    if size > MAX_FILE_SIZE:
        raise ValueError(f"Tệp vượt giới hạn {MAX_FILE_SIZE // (1024*1024)} MB.")
    return size
