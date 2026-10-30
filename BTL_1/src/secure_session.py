"""
secure_session.py — Adapter giữa handshake.SessionKeys và giao diện
encrypt/decrypt mà client.py sử dụng.
"""

from __future__ import annotations

try:
    from . import crypto, handshake
except ImportError:
    import crypto
    import handshake


class SecureSession:
    """Bọc SessionKeys; chuyển nonce thành hex để JSON hóa được."""

    def __init__(self, keys: "handshake.SessionKeys") -> None:
        self.keys = keys

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> tuple[str, bytes]:
        nonce, ct = crypto.aes_gcm_encrypt(self.keys.send_key, plaintext, aad=aad)
        return nonce.hex(), ct

    def decrypt(self, nonce_hex: str, ciphertext: bytes, aad: bytes = b"") -> bytes:
        nonce = bytes.fromhex(nonce_hex)
        return crypto.aes_gcm_decrypt(self.keys.receive_key, nonce, ciphertext, aad=aad)

    def make_confirmation(self) -> bytes:
        return self.keys.make_confirmation()

    def verify_confirmation(self, blob: bytes) -> None:
        self.keys.verify_confirmation(blob)