"""Tạo khóa Ed25519 cho một thành viên và ghi khóa công khai vào members.json."""
import json
import os
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from config import KEYS_DIR, MEMBERS_FILE

def main():
    if len(sys.argv) != 3:
        print("Cách dùng: python setup_identity.py TEN MSSV")
        raise SystemExit(2)
    name, mssv = sys.argv[1].strip(), sys.argv[2].strip()
    if not name or len(name) > 32 or not mssv or mssv == "CHANGE_ME":
        print("Tên và MSSV phải hợp lệ.")
        raise SystemExit(2)
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(MEMBERS_FILE), exist_ok=True)
    key_path = os.path.join(KEYS_DIR, f"{name}_ed25519_private.pem")
    if os.path.exists(key_path):
        print(f"Đã tồn tại {key_path}; không ghi đè khóa riêng.")
        print("Nếu đây là khóa hiện tại của bạn, hãy dùng khóa công khai đã đăng ký.")
        raise SystemExit(1)
    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    with open(key_path, "wb") as f:
        f.write(pem)
    try:
        with open(MEMBERS_FILE, "r", encoding="utf-8") as f:
            members = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        members = {}
    members[name] = {"mssv": mssv, "public_key": public_raw.hex()}
    with open(MEMBERS_FILE, "w", encoding="utf-8") as f:
        json.dump(members, f, ensure_ascii=False, indent=2)
    print(f"Đã tạo khóa riêng: {key_path}")
    print(f"MSSV: {mssv}")
    print(f"Khóa công khai Ed25519 (hãy trao đổi qua kênh tin cậy):\n{public_raw.hex()}")
    print(f"Đã cập nhật {MEMBERS_FILE}")
    print("Không gửi file khóa riêng cho thành viên khác. Chỉ trao đổi khóa công khai.")

if __name__ == "__main__":
    main()
