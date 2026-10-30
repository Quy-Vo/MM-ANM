import os

HOST = os.environ.get("E2E_HOST", "127.0.0.1")
PORT = int(os.environ.get("E2E_PORT", "50000"))
MAX_MESSAGE_SIZE = 2 * 1024 * 1024
CHUNK_SIZE = 48 * 1024
MAX_FILE_SIZE = 50 * 1024 * 1024
DOWNLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "downloads")
ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
MEMBERS_FILE = os.path.join(ROOT_DIR, "members.json")
KEYS_DIR = os.path.join(ROOT_DIR, "keys")
