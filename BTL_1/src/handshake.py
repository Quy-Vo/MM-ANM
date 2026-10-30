"""
handshake.py — Authenticated ephemeral key-exchange for the E2E chat project.

Flow (2 messages + key confirmation):

    Initiator (A)                                   Responder (B)
    -------------                                   -------------
    1. sinh X25519 tạm thời + nonce_A
       ClientHello = (eph_A, nonce_A, Sig_A)  --->  2. verify Sig_A bằng khóa Ed25519
                                                       của A đã pin sẵn
                                                    3. sinh X25519 tạm thời + nonce_B
                                              <---  ServerHello = (eph_B, nonce_B, Sig_B)
    4. verify Sig_B bằng khóa Ed25519 của B            (Sig_B ràng buộc cả ClientHello)
       đã pin sẵn
    5. Cả hai: DH -> shared secret -> HKDF -> (key A->B, key B->A)
    6. Key confirmation: mỗi bên gửi 1 gói AES-GCM; bên kia giải mã được
       thì chứng tỏ hai bên có cùng khóa phiên.

Các quyết định thiết kế:
- Khóa Ed25519 của đối phương PHẢI được pin/cấu hình trước. Chữ ký chỉ chống
  MITM nếu khóa xác minh không thể bị thay thế.
- Chữ ký bao gồm: nhãn giao thức, role, khóa công khai tạm thời, nonce, và
  digest MSSV. Nếu hai bên cấu hình MSSV khác nhau (hoặc khác thứ tự) thì
  chữ ký không xác minh được và handshake thất bại.
- ServerHello ký thêm cả ClientHello, nên chữ ký B gắn với đúng phiên này
  (chống replay / ghép nối giữa các phiên).
- Khóa AES được dẫn xuất từ bí mật chung DH bằng HKDF. Digest MSSV chỉ là
  một phần của salt/ngữ cảnh, KHÔNG BAO GIỜ dùng trực tiếp làm khóa.
- Dùng hai khóa riêng cho hai chiều (A->B và B->A).
- Khóa riêng tạm thời được bỏ ngay sau khi tính DH (forward secrecy).

Dùng:
    initiator = Initiator(a_identity_private, b_identity_public, mssvs)
    responder = Responder(b_identity_private, a_identity_public, mssvs)

    client_hello = initiator.start()                       # A -> B
    server_hello, b_keys = responder.respond(client_hello) # B -> A
    a_keys = initiator.finish(server_hello)

    confirm_a = a_keys.make_confirmation()                 # A -> B
    b_keys.verify_confirmation(confirm_a)
    confirm_b = b_keys.make_confirmation()                 # B -> A
    a_keys.verify_confirmation(confirm_b)
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass, field
from typing import Iterable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from . import crypto
except ImportError:  # chạy khi srcs/ nằm trong sys.path
    import crypto


PROTOCOL_VERSION = 1
ROLE_INITIATOR = 1
ROLE_RESPONDER = 2

PUBLIC_KEY_LENGTH = 32
NONCE_LENGTH = 32


_LABEL = b"e2e-chat/handshake/v1"
_KDF_CONTEXT = b"e2e-chat/directional-keys/v1"
_CONFIRM_PLAINTEXT = b"e2e-chat/key-confirmation/v1"


class HandshakeError(Exception):
    """Handshake thất bại (chữ ký sai, dữ liệu hỏng, cấu hình không khớp, ...)."""


# --------------------------------------------------------------------------- #
# Thông điệp Hello
# --------------------------------------------------------------------------- #
# Trong file handshake.py

@dataclass(frozen=True)
class Hello:
    """Một thông điệp handshake: version | role | hello_str_len | hello_str | eph_pub | nonce | signature."""
    role: int
    hello_str: bytes
    ephemeral_public: bytes
    nonce: bytes
    signature: bytes

    def body(self) -> bytes:
        # Cấu trúc: Version(1) + Role(1) + StrLen(2) + HelloStr(N) + EPH(32) + Nonce(32)
        return bytes([PROTOCOL_VERSION, self.role]) + len(self.hello_str).to_bytes(2, "big") + \
               self.hello_str + self.ephemeral_public + self.nonce

    def to_bytes(self) -> bytes:
        return self.body() + self.signature

    @classmethod
    def from_bytes(cls, data: bytes, expected_role: int) -> "Hello":
        data = bytes(data)
        if len(data) < 6:
            raise HandshakeError("Hello quá ngắn")
        if data[0] != PROTOCOL_VERSION:
            raise HandshakeError("Phiên bản giao thức không được hỗ trợ")
        if data[1] != expected_role:
            raise HandshakeError("Sai role trong Hello")
        
        str_len = int.from_bytes(data[2:4], "big")
        offset = 4 + str_len
        if len(data) != offset + 32 + 32 + 64:
            raise HandshakeError("Độ dài Hello không hợp lệ")
            
        return cls(
            role=data[1],
            hello_str=data[4:offset],
            ephemeral_public=data[offset:offset+32],
            nonce=data[offset+32:offset+64],
            signature=data[offset+64:]
        )

def _signed_data(hello_body: bytes, mssv_digest: bytes, initiator_body: bytes = b"") -> bytes:
    return _LABEL + b"/signature" + hello_body + mssv_digest + initiator_body
def _transcript_hash(mssv_digest: bytes, initiator_body: bytes, responder_body: bytes) -> bytes:
    return crypto.sha256_bytes(
        _LABEL + b"/transcript" + mssv_digest + initiator_body + responder_body
    )

# Hàm tạo chuỗi MSSV:
def build_hello_string(mssvs: Iterable[str]) -> bytes:
    return ("Hello, We are " + ", ".join(mssvs)).encode("utf-8")

# --------------------------------------------------------------------------- #
# Khóa phiên
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SessionKeys:
    """Khóa phiên theo từng chiều và hash transcript của handshake."""

    role: int
    send_key: bytes = field(repr=False)
    receive_key: bytes = field(repr=False)
    transcript_hash: bytes

    def _aad(self, sender_role: int) -> bytes:
        return self.transcript_hash + bytes([sender_role])

    def make_confirmation(self) -> bytes:
        """Tạo gói xác nhận khóa: nonce(12) || ciphertext+tag, mã hóa bằng send_key."""
        nonce, ciphertext = crypto.aes_gcm_encrypt(
            self.send_key, _CONFIRM_PLAINTEXT, aad=self._aad(self.role)
        )
        return nonce + ciphertext

    def verify_confirmation(self, blob: bytes) -> None:
        """Giải mã gói xác nhận của đối phương; ném HandshakeError nếu không khớp."""
        blob = bytes(blob)
        if len(blob) <= crypto.AES_GCM_NONCE_LENGTH:
            raise HandshakeError("Gói xác nhận khóa quá ngắn")
        peer_role = ROLE_RESPONDER if self.role == ROLE_INITIATOR else ROLE_INITIATOR
        nonce = blob[:crypto.AES_GCM_NONCE_LENGTH]
        ciphertext = blob[crypto.AES_GCM_NONCE_LENGTH:]
        try:
            plaintext = crypto.aes_gcm_decrypt(
                self.receive_key, nonce, ciphertext, aad=self._aad(peer_role)
            )
        except InvalidTag as exc:
            raise HandshakeError("Xác nhận khóa thất bại: hai bên không có cùng khóa phiên") from exc
        if not hmac.compare_digest(plaintext, _CONFIRM_PLAINTEXT):
            raise HandshakeError("Nội dung xác nhận khóa không đúng")


def _derive_session_keys(
    shared_secret: bytes,
    mssv_digest: bytes,
    initiator_hello: Hello,
    responder_hello: Hello,
    role: int,
) -> SessionKeys:
    transcript = _transcript_hash(mssv_digest, initiator_hello.body(), responder_hello.body())
    salt = crypto.sha256_bytes(
        _LABEL + b"/salt" + mssv_digest + initiator_hello.nonce + responder_hello.nonce
    )
    key_i_to_r, key_r_to_i = crypto.derive_directional_keys(
        shared_secret, salt=salt, context=_KDF_CONTEXT + transcript
    )
    if role == ROLE_INITIATOR:
        send_key, receive_key = key_i_to_r, key_r_to_i
    else:
        send_key, receive_key = key_r_to_i, key_i_to_r
    return SessionKeys(
        role=role,
        send_key=send_key,
        receive_key=receive_key,
        transcript_hash=transcript,
    )


# --------------------------------------------------------------------------- #
# Hai phía của handshake
# --------------------------------------------------------------------------- #
class _Party:
    def __init__(
        self,
        identity_private_key: Ed25519PrivateKey,
        peer_identity_public: bytes,
        mssvs: Iterable[str],
    ) -> None:
        if len(peer_identity_public) != PUBLIC_KEY_LENGTH:
            raise ValueError("Khóa công khai Ed25519 của đối phương phải dài 32 byte")
        self._identity_private = identity_private_key
        self._peer_identity_public = bytes(peer_identity_public)
        self._mssv_digest = crypto.hash_mssvs(mssvs)
        self._mssvs = list(mssvs)  # <--- THÊM DÒNG NÀY
        
        # Khóa DH mới cho MỖI phiên.
        self._eph_private, self._eph_public = crypto.generate_x25519_keypair()
        self._consumed = False

    def _consume(self) -> None:
        """Mỗi đối tượng chỉ chạy handshake một lần."""
        if self._consumed:
            raise HandshakeError("Đối tượng handshake chỉ dùng được một lần")
        self._consumed = True

    def _dh(self, peer_ephemeral_public: bytes) -> bytes:
        try:
            secret = crypto.x25519_shared_secret(self._eph_private, peer_ephemeral_public)
        except ValueError as exc:
            raise HandshakeError("Khóa công khai DH của đối phương không hợp lệ") from exc
        finally:
            self._eph_private = None  # forward secrecy: bỏ khóa riêng tạm thời
        if hmac.compare_digest(secret, bytes(len(secret))):
            raise HandshakeError("Bí mật DH toàn số 0 (khóa công khai bậc thấp)")
        return secret

    def _verify_peer(self, hello: Hello, initiator_body: bytes = b"") -> None:
        data = _signed_data(hello.body(), self._mssv_digest, initiator_body)
        if not crypto.ed25519_verify(self._peer_identity_public, data, hello.signature):
            raise HandshakeError(
                "Chữ ký không hợp lệ (sai khóa đã pin, bị sửa đổi, hoặc cấu hình MSSV không khớp)"
            )


class Initiator(_Party):
    """Bên khởi tạo (A): start() -> ClientHello, finish(ServerHello) -> SessionKeys."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._hello: Hello | None = None

    def start(self) -> bytes:
        if self._hello is not None:
            raise HandshakeError("start() đã được gọi")
        nonce = os.urandom(NONCE_LENGTH)
        hello_str = build_hello_string(self._mssvs)
        unsigned = Hello(ROLE_INITIATOR, hello_str, self._eph_public, nonce, b"")
        signature = crypto.ed25519_sign(
            self._identity_private, _signed_data(unsigned.body(), self._mssv_digest)
        )
        self._hello = Hello(ROLE_INITIATOR, hello_str, self._eph_public, nonce, signature)
        return self._hello.to_bytes()

    def finish(self, server_hello_bytes: bytes) -> SessionKeys:
        if self._hello is None:
            raise HandshakeError("Phải gọi start() trước finish()")
        self._consume()
        server_hello = Hello.from_bytes(server_hello_bytes, ROLE_RESPONDER)
        self._verify_peer(server_hello, initiator_body=self._hello.body())
        secret = self._dh(server_hello.ephemeral_public)
        return _derive_session_keys(
            secret, self._mssv_digest, self._hello, server_hello, ROLE_INITIATOR
        )


class Responder(_Party):
    """Bên phản hồi (B): respond(ClientHello) -> (ServerHello, SessionKeys)."""

    def respond(self, client_hello_bytes: bytes) -> tuple[bytes, SessionKeys]:
        self._consume()
        client_hello = Hello.from_bytes(client_hello_bytes, ROLE_INITIATOR)
        self._verify_peer(client_hello)

        nonce = os.urandom(NONCE_LENGTH)
        hello_str = build_hello_string(self._mssvs)
        unsigned = Hello(ROLE_RESPONDER, hello_str, self._eph_public, nonce, b"")
        signature = crypto.ed25519_sign(
            self._identity_private,
            _signed_data(unsigned.body(), self._mssv_digest, client_hello.body()),
        )
        server_hello = Hello(ROLE_RESPONDER, hello_str, self._eph_public, nonce, signature)

        secret = self._dh(client_hello.ephemeral_public)
        keys = _derive_session_keys(
            secret, self._mssv_digest, client_hello, server_hello, ROLE_RESPONDER
        )
        return server_hello.to_bytes(), keys
