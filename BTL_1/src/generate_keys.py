"""
generate_keys.py — Sinh cặp khóa Ed25519 cho các thành viên demo.

Cách dùng:
    python generate_keys.py Alice Bob

Sinh ra:
    keys/Alice.priv   (32 byte raw)
    keys/Alice.pub    (32 byte raw)
    keys/Bob.priv
    keys/Bob.pub

Trong demo, khóa .pub đóng vai "pinned key" trao đổi ngoài kênh.
Client chỉ load .pub của peer mình cần nhắn; không có .pub = không tin.
"""
import os
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

KEYS_DIR = os.environ.get("CHAT_KEYS_DIR", "keys")


def generate(name: str) -> None:
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    with open(os.path.join(KEYS_DIR, f"{name}.priv"), "wb") as f:
        f.write(priv_bytes)
    with open(os.path.join(KEYS_DIR, f"{name}.pub"), "wb") as f:
        f.write(pub_bytes)
    print(f"OK {name}: keys/{name}.priv + keys/{name}.pub")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python generate_keys.py NAME [NAME ...]")
        sys.exit(1)
    os.makedirs(KEYS_DIR, exist_ok=True)
    for name in sys.argv[1:]:
        generate(name)


if __name__ == "__main__":
    main()