import hashlib
import os
from config import MAX_FILE_SIZE

def validate_file(path: str) -> int:
    size = os.path.getsize(path)
    if size < 0 or size > MAX_FILE_SIZE:
        raise ValueError(f"Tệp vượt giới hạn {MAX_FILE_SIZE} byte.")
    return size

def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
