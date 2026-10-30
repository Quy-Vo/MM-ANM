"""
crypto.py — Cryptographic primitives for 
the E2E chat/file-transfer project.

Algorithms:
- X25519: Diffie–Hellman key agreement
- HKDF-SHA256: session-key derivation
- AES-256-GCM: authenticated encryption
- Ed25519: digital signatures
- SHA-256: MSSV digest and file hashing


Security notes:
- Never transmit or log private keys or shared secrets.
- Authenticate the Ed25519 public key through a trusted mechanism (for this
  project, it may be pinned/configured in advance). A signature alone does
  not prevent MITM if the verification key itself can be replaced.
- Never reuse an AES-GCM nonce with the same key.
- The MSSV digest is predictable and MUST NOT be used by itself as an AES key.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import BinaryIO, Iterable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


AES_KEY_LENGTH = 32       # 32 bytes = 256 bits
AES_GCM_NONCE_LENGTH = 12 # 12 bytes = 96 bits, recommended for GCM
SHA256_LENGTH = 32
ED25519_SIGNATURE_LENGTH = 64


def generate_x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    """Generate an ephemeral X25519 private key 
        and return its public key bytes."""
    private_key = X25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_key_bytes


def x25519_shared_secret(
    private_key: X25519PrivateKey,
    peer_public_key_bytes: bytes,
) -> bytes:
    """
    Calculate the DH shared secret using our private key 
    and peer's raw public key.

    The returned secret is input to a KDF; 
    do not use it directly as an AES key.
    """
    if len(peer_public_key_bytes) != 32:
        raise ValueError("X25519 public key must be exactly 32 bytes")

    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    return private_key.exchange(peer_public_key)


def derive_key(
    shared_secret: bytes,
    *,
    salt: bytes,
    info: bytes = b"e2e-chat/session-key/v1",
    length: int = AES_KEY_LENGTH,
) -> bytes:
    """
    Derive key material from a DH shared secret using HKDF-SHA256.

    Both peers must use identical salt, info, length, and shared secret.
    The salt/context may incorporate the agreed MSSV digest and handshake
    context, but the predictable MSSV digest is not a replacement for the
    DH shared secret.
    """
    if not shared_secret:
        raise ValueError("shared_secret must not be empty")
    if length <= 0 or length > 255 * SHA256_LENGTH:
        raise ValueError("Invalid HKDF output length")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(shared_secret)


def derive_directional_keys(
    shared_secret: bytes,
    *,
    salt: bytes,
    context: bytes = b"e2e-chat/directional-keys/v1",
) -> tuple[bytes, bytes]:
    """
    Derive separate 256-bit keys for A->B and B->A.

    Both peers must agree on the meaning/order of the returned pair.
    For example, A uses the first key to send and the second to receive;
    B uses the first to receive and the second to send.
    """
    material = derive_key(
        shared_secret,
        salt=salt,
        info=context,
        length=2 * AES_KEY_LENGTH,
    )
    return material[:AES_KEY_LENGTH], material[AES_KEY_LENGTH:]


def aes_gcm_encrypt(
    key: bytes,
    plaintext: bytes,
    *,
    aad: bytes | None = None,
) -> tuple[bytes, bytes]:
    """
    Encrypt bytes with AES-256-GCM.

    Returns (nonce, ciphertext_with_authentication_tag).
    Store/transmit the nonce beside the ciphertext; the nonce is not secret.
    """
    if len(key) != AES_KEY_LENGTH:
        raise ValueError("AES-256-GCM key must be exactly 32 bytes")

    nonce = os.urandom(AES_GCM_NONCE_LENGTH)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def aes_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    *,
    aad: bytes | None = None,
) -> bytes:
    """
    Authenticate and decrypt AES-GCM data.

    Raises InvalidTag if the ciphertext, tag, nonce, key, or AAD is incorrect.
    Callers must not use plaintext unless this function returns successfully.
    """
    if len(key) != AES_KEY_LENGTH:
        raise ValueError("AES-256-GCM key must be exactly 32 bytes")
    if len(nonce) != AES_GCM_NONCE_LENGTH:
        raise ValueError("AES-GCM nonce must be exactly 12 bytes")

    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    """Generate an Ed25519 signing key and return its raw public key bytes."""
    private_key = Ed25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_key_bytes


def ed25519_sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    """Sign a message using Ed25519; returns a 64-byte signature."""
    return private_key.sign(message)


def ed25519_verify(
    public_key_bytes: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    """
    Verify an Ed25519 signature.

    Returns False for an invalid signature. Malformed public-key lengths raise
    ValueError so programming/protocol errors are not silently hidden.
    """
    if len(public_key_bytes) != 32:
        raise ValueError("Ed25519 public key must be exactly 32 bytes")
    if len(signature) != ED25519_SIGNATURE_LENGTH:
        return False

    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def hash_mssvs(mssvs: Iterable[str]) -> bytes:
    """
    Return SHA-256(MSSV_1 || MSSV_2 || ...), as required by the assignment.

    Input order is preserved and no delimiter is inserted, matching the
    assignment's concatenation notation. All members must use the same order.
    Returns the 32-byte digest, not a recommended standalone AES key.
    """
    values = list(mssvs)
    if not values:
        raise ValueError("At least one MSSV is required")
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError("Every MSSV must be a non-empty string")

    joined = "".join(values).encode("utf-8")
    return hashlib.sha256(joined).digest()


def sha256_bytes(data: bytes) -> bytes:
    """Return the 32-byte SHA-256 digest of bytes."""
    return hashlib.sha256(data).digest()


def sha256_file(file_path: str | os.PathLike[str]) -> bytes:
    """Calculate a file's SHA-256 digest incrementally, suitable for large files."""
    digest = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.digest()


def to_hex(data: bytes) -> str:
    """Convert bytes to lowercase hexadecimal for display/logging."""
    return data.hex()


def from_hex(hex_string: str) -> bytes:
    """Convert a hexadecimal string to bytes."""
    try:
        return bytes.fromhex(hex_string)
    except ValueError as exc:
        raise ValueError("Input is not a valid hexadecimal string") from exc
