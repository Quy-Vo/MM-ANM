# HOST = "127.0.0.1"
# PORT = 50000
# MAX_MESSAGE_SIZE = 2 * 1024 * 1024
# CHUNK_SIZE = 64 * 1024
# MAX_FILE_SIZE = 50 * 1024 * 1024
# DOWNLOAD_DIR = "downloads"
import os

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
