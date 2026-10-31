"""
secure_session.py — Adapter giữa handshake.SessionKeys và giao diện encrypt/decrypt của client.py.

Chống replay / đảo thứ tự:
- Mỗi gói gửi đi có counter tăng dần (0, 1, 2, ...) theo từng chiều.
- Counter nằm trong AAD của AES-GCM nên không thể sửa mà không bị phát hiện.
- Bên nhận chỉ chấp nhận counter LỚN HƠN counter hợp lệ gần nhất; chỉ cập nhật sau khi xác thực thành công.
Header gửi đi có dạng "<counter>:<nonce_hex>" (nonce 12 byte do crypto.aes_gcm_encrypt sinh ngẫu nhiên).
"""

from __future__ import annotations

import re
import struct
import threading

from cryptography.exceptions import InvalidTag

try:
    from . import crypto, handshake
except ImportError:
    import crypto
    import handshake


class SessionError(ValueError):
    """Gói không hợp lệ: sai xác thực, replay, sai định dạng header."""


_HDR_RE = re.compile(r"^([0-9]{1,19}):([0-9a-f]{24})$")
MAX_COUNTER = 2 ** 63


class SecureSession:
    def __init__(self, keys: "handshake.SessionKeys") -> None:
        self.keys = keys
        self._send_counter = 0
        self._last_recv = -1
        self._lock = threading.Lock()

    @staticmethod
    def _aad(aad: bytes, counter: int) -> bytes:
        return aad + b"|" + struct.pack("!Q", counter)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> tuple[str, bytes]:
        with self._lock:
            counter = self._send_counter
            if counter >= MAX_COUNTER:
                raise SessionError("Hết bộ đếm, cần handshake lại")
            self._send_counter += 1
        nonce, ct = crypto.aes_gcm_encrypt(self.keys.send_key, plaintext, aad=self._aad(aad, counter))
        return f"{counter}:{nonce.hex()}", ct

    def decrypt(self, hdr: str, ciphertext: bytes, aad: bytes = b"") -> bytes:
        match = _HDR_RE.match(hdr) if isinstance(hdr, str) else None
        if not match:
            raise SessionError("Header gói mã hóa không hợp lệ")
        counter = int(match.group(1))
        if counter >= MAX_COUNTER:
            raise SessionError("Counter không hợp lệ")
        nonce = bytes.fromhex(match.group(2))
        with self._lock:
            if counter <= self._last_recv:
                raise SessionError("Replay hoặc sai thứ tự: counter không tăng")
        try:
            plaintext = crypto.aes_gcm_decrypt(self.keys.receive_key, nonce, ciphertext, aad=self._aad(aad, counter))
        except InvalidTag as exc:
            raise SessionError("Xác thực thất bại: dữ liệu bị sửa hoặc sai khóa") from exc
        with self._lock:
            self._last_recv = counter  # chỉ cập nhật SAU khi xác thực thành công
        return plaintext

    def make_confirmation(self) -> bytes:
        return self.keys.make_confirmation()

    def verify_confirmation(self, blob: bytes) -> None:
        self.keys.verify_confirmation(blob)
