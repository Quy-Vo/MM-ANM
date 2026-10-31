# HOST = "127.0.0.1"
# PORT = 50000
# MAX_MESSAGE_SIZE = 2 * 1024 * 1024
# CHUNK_SIZE = 64 * 1024
# MAX_FILE_SIZE = 50 * 1024 * 1024
# DOWNLOAD_DIR = "downloads"
import os
import sys

# Windows: khi stdout bị chuyển hướng (file/pipe), Python dùng bảng mã cũ (cp1252) và in tiếng Việt sẽ báo
# UnicodeEncodeError. Ép UTF-8 cho mọi script (config.py được import bởi tất cả).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, OSError):
        pass

HOST = os.environ.get("CHAT_HOST", "127.0.0.1")
PORT = int(os.environ.get("CHAT_PORT", "50000"))
MAX_MESSAGE_SIZE = 2 * 1024 * 1024
CHUNK_SIZE = 64 * 1024
MAX_FILE_SIZE = 50 * 1024 * 1024
DOWNLOAD_DIR = "downloads"

# --- A + C: cấu hình cho E2E handshake ---
KEYS_DIR = os.environ.get("CHAT_KEYS_DIR", "keys")

MSSVS = ["2412915", "2413675", "2412965"]

HANDSHAKE_TIMEOUT = 15.0  # giây
