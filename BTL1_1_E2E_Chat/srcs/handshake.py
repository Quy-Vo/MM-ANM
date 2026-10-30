
"""
handshake.py

Authenticated key exchange for the E2E chat/file-transfer project.

Protocol:
    1. Initiator -> Responder: HELLO
    2. Responder -> Initiator: HELLO_REPLY
    3. Initiator -> Responder: AUTH

Cryptographic primitives are imported from crypto.py:
    X25519, HKDF-SHA256, Ed25519, SHA-256.
"""

from __future__ import annotations

import hashlib
import json
import secrets

from dataclasses import dataclass
from typing import Any

import crypto


PROTOCOL_VERSION = "1.0"

# Domain separation: prevent signatures from being reused
# in another protocol or another purpose.
SIGNATURE_CONTEXT = b"E2E-CHAT-HANDSHAKE-V1"

# HKDF context for deriving directional session keys.
KDF_CONTEXT = b"E2E-CHAT-SESSION-KEYS-V1"


class HandshakeError(Exception):
    """Raised when the handshake protocol fails."""


@dataclass
class SessionKeys:
    """
    Session keys generated after successful authentication.

    Initiator:
        send_key     = initiator -> responder
        receive_key  = responder -> initiator

    Responder:
        send_key     = responder -> initiator
        receive_key  = initiator -> responder
    """

    session_id: str
    send_key: bytes
    receive_key: bytes


@dataclass
class InitiatorState:
    """Temporary state maintained by the initiating client."""

    initiator_mssv: str
    responder_mssv: str
    group_mssvs: tuple[str, ...]
    session_id: str

    private_key: Any
    public_key: bytes
    nonce: bytes

    hello: dict


@dataclass
class ResponderState:
    """Temporary state maintained by the responding client."""

    initiator_mssv: str
    responder_mssv: str
    group_mssvs: tuple[str, ...]
    session_id: str

    private_key: Any
    public_key: bytes
    nonce: bytes

    hello: dict
    hello_reply: dict


# ---------------------------------------------------------------------
# Serialization and validation
# ---------------------------------------------------------------------

def canonical_json(data: dict) -> bytes:
    """
    Serialize a dictionary deterministically.

    Both clients must sign exactly the same byte sequence.
    """

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _require_string(data: dict, field: str) -> str:
    value = data.get(field)

    if not isinstance(value, str) or not value:
        raise HandshakeError(f"Invalid or missing field: {field}")

    return value


def _require_hex(data: dict, field: str, expected_length: int) -> bytes:
    value = _require_string(data, field)

    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise HandshakeError(f"Invalid hexadecimal field: {field}") from exc

    if len(decoded) != expected_length:
        raise HandshakeError(f"Invalid length for field: {field}")

    return decoded


def _validate_message_type(message: dict, expected_type: str) -> None:
    if not isinstance(message, dict):
        raise HandshakeError("Message must be a dictionary")

    if message.get("type") != expected_type:
        raise HandshakeError(
            f"Expected {expected_type}, got {message.get('type')}"
        )

    if message.get("version") != PROTOCOL_VERSION:
        raise HandshakeError("Unsupported protocol version")


# ---------------------------------------------------------------------
# Handshake transcript
# ---------------------------------------------------------------------

def build_transcript(hello: dict, hello_reply: dict) -> bytes:
    """
    Build the canonical transcript authenticated by both parties.

    It binds:
        - protocol version
        - both identities
        - session ID
        - both nonces
        - both X25519 public keys
    """

    _validate_message_type(hello, "HELLO")
    _validate_message_type(hello_reply, "HELLO_REPLY")

    if hello.get("session_id") != hello_reply.get("session_id"):
        raise HandshakeError("Session ID mismatch")

    if hello.get("initiator_mssv") != hello_reply.get("initiator_mssv"):
        raise HandshakeError("Initiator identity mismatch")

    if hello.get("responder_mssv") != hello_reply.get("responder_mssv"):
        raise HandshakeError("Responder identity mismatch")

    transcript = {
        "version": PROTOCOL_VERSION,
        "session_id": hello["session_id"],
        "initiator_mssv": hello["initiator_mssv"],
        "responder_mssv": hello["responder_mssv"],
        "group_mssvs": hello["group_mssvs"],
        "initiator_nonce": hello["nonce"],
        "responder_nonce": hello_reply["nonce"],
        "initiator_dh_public_key": hello["dh_public_key"],
        "responder_dh_public_key": hello_reply["dh_public_key"],
    }

    return canonical_json(transcript)


def _signed_transcript(transcript: bytes, role: str) -> bytes:
    """
    Add domain separation and role binding to the signed data.
    """

    return (
        SIGNATURE_CONTEXT
        + b"|"
        + role.encode("ascii")
        + b"|"
        + hashlib.sha256(transcript).digest()
    )


# ---------------------------------------------------------------------
# Step 1: Initiator creates HELLO
# ---------------------------------------------------------------------

def create_hello(
    initiator_mssv: str,
    responder_mssv: str,
    group_mssvs: list[str] | tuple[str, ...] | None = None,
) -> tuple[InitiatorState, dict]:
    """
    Generate initiator X25519 keys and create HELLO.

    The MSSV greeting follows the assignment's required format.
    """

    if not initiator_mssv or not responder_mssv:
        raise ValueError("MSSV must not be empty")

    group_mssvs = tuple(group_mssvs or (initiator_mssv, responder_mssv))
    if not group_mssvs or any(not isinstance(x, str) or not x for x in group_mssvs):
        raise ValueError("Group MSSVs must be non-empty strings")
    if initiator_mssv not in group_mssvs or responder_mssv not in group_mssvs:
        raise ValueError("Both handshake participants must be in group MSSVs")

    private_key, public_key = crypto.generate_x25519_keypair()

    nonce = secrets.token_bytes(32)
    session_id = secrets.token_hex(16)

    hello = {
        "type": "HELLO",
        "version": PROTOCOL_VERSION,

        "greeting": "Hello, We are " + ", ".join(group_mssvs),
        "group_mssvs": list(group_mssvs),

        "initiator_mssv": initiator_mssv,
        "responder_mssv": responder_mssv,

        "session_id": session_id,
        "nonce": nonce.hex(),
        "dh_public_key": public_key.hex(),
    }

    state = InitiatorState(
        initiator_mssv=initiator_mssv,
        responder_mssv=responder_mssv,
        group_mssvs=group_mssvs,
        session_id=session_id,
        private_key=private_key,
        public_key=public_key,
        nonce=nonce,
        hello=hello,
    )

    return state, hello


# ---------------------------------------------------------------------
# Step 2: Responder processes HELLO and creates HELLO_REPLY
# ---------------------------------------------------------------------

def accept_hello(
    hello: dict,
    responder_signing_private_key,
    expected_group_mssvs: list[str] | tuple[str, ...] | None = None,
) -> tuple[ResponderState, dict]:
    """
    Validate HELLO and create signed HELLO_REPLY.

    responder_signing_private_key:
        Ed25519 private key belonging to the responder.
    """

    _validate_message_type(hello, "HELLO")

    initiator_mssv = _require_string(hello, "initiator_mssv")
    responder_mssv = _require_string(hello, "responder_mssv")

    if not isinstance(hello.get("greeting"), str):
        raise HandshakeError("Missing greeting")

    received_group = hello.get("group_mssvs")
    if not isinstance(received_group, list) or not received_group or any(not isinstance(x, str) or not x for x in received_group):
        raise HandshakeError("Invalid group MSSV list")
    group_mssvs = tuple(received_group)
    if initiator_mssv not in group_mssvs or responder_mssv not in group_mssvs:
        raise HandshakeError("Handshake participants are missing from group MSSV list")
    if expected_group_mssvs is not None and group_mssvs != tuple(expected_group_mssvs):
        raise HandshakeError("Group MSSV list does not match local configuration")
    expected_greeting = "Hello, We are " + ", ".join(group_mssvs)
    if hello["greeting"] != expected_greeting:
        raise HandshakeError("Invalid MSSV greeting")

    session_id = _require_string(hello, "session_id")

    _require_hex(hello, "nonce", 32)
    _require_hex(hello, "dh_public_key", 32)

    private_key, public_key = crypto.generate_x25519_keypair()

    nonce = secrets.token_bytes(32)

    hello_reply = {
        "type": "HELLO_REPLY",
        "version": PROTOCOL_VERSION,

        "initiator_mssv": initiator_mssv,
        "responder_mssv": responder_mssv,
        "group_mssvs": list(group_mssvs),

        "session_id": session_id,
        "nonce": nonce.hex(),
        "dh_public_key": public_key.hex(),
    }

    transcript = build_transcript(hello, hello_reply)

    signature = crypto.ed25519_sign(
        responder_signing_private_key,
        _signed_transcript(transcript, "RESPONDER"),
    )

    hello_reply["signature"] = signature.hex()

    state = ResponderState(
        initiator_mssv=initiator_mssv,
        responder_mssv=responder_mssv,
        group_mssvs=group_mssvs,
        session_id=session_id,
        private_key=private_key,
        public_key=public_key,
        nonce=nonce,
        hello=hello,
        hello_reply=hello_reply,
    )

    return state, hello_reply


# ---------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------

def _derive_session_keys(
    private_key,
    peer_public_key: bytes,
    initiator_mssv: str,
    responder_mssv: str,
    group_mssvs: tuple[str, ...],
    transcript: bytes,
    session_id: str,
    role: str,
) -> SessionKeys:
    """
    Derive two independent directional AES-256-GCM keys.

    The assignment's MSSV hash is used as HKDF salt.
    The X25519 shared secret remains the secret input to HKDF.
    """

    shared_secret = crypto.x25519_shared_secret(
        private_key,
        peer_public_key,
    )

    # SHA-256 of all group MSSVs in the agreed order (Quân, Quý, Trọng).
    mssv_salt = crypto.hash_mssvs(group_mssvs)

    # Bind derived keys to this specific handshake transcript.
    context = (
        KDF_CONTEXT
        + b"|"
        + session_id.encode("utf-8")
        + b"|"
        + hashlib.sha256(transcript).digest()
    )

    initiator_to_responder, responder_to_initiator = (
        crypto.derive_directional_keys(
            shared_secret,
            salt=mssv_salt,
            context=context,
        )
    )

    if role == "initiator":
        return SessionKeys(
            session_id=session_id,
            send_key=initiator_to_responder,
            receive_key=responder_to_initiator,
        )

    if role == "responder":
        return SessionKeys(
            session_id=session_id,
            send_key=responder_to_initiator,
            receive_key=initiator_to_responder,
        )

    raise ValueError("Unknown handshake role")


# ---------------------------------------------------------------------
# Step 3: Initiator verifies HELLO_REPLY and creates AUTH
# ---------------------------------------------------------------------

def verify_reply_and_create_auth(
    state: InitiatorState,
    hello_reply: dict,
    responder_signing_public_key: bytes,
    initiator_signing_private_key,
) -> tuple[dict, SessionKeys]:
    """
    Initiator:
        1. Validates HELLO_REPLY.
        2. Verifies responder's Ed25519 signature.
        3. Signs the same transcript.
        4. Derives directional session keys.
        5. Returns AUTH and session keys.
    """

    _validate_message_type(hello_reply, "HELLO_REPLY")

    if hello_reply.get("session_id") != state.session_id:
        raise HandshakeError("Session ID mismatch")

    if hello_reply.get("initiator_mssv") != state.initiator_mssv:
        raise HandshakeError("Initiator MSSV mismatch")

    if hello_reply.get("responder_mssv") != state.responder_mssv:
        raise HandshakeError("Responder MSSV mismatch")
    if tuple(hello_reply.get("group_mssvs", [])) != state.group_mssvs:
        raise HandshakeError("Group MSSV list mismatch")

    _require_hex(hello_reply, "nonce", 32)
    peer_public_key = _require_hex(
        hello_reply, "dh_public_key", 32
    )
    signature = _require_hex(
        hello_reply, "signature", 64
    )

    transcript = build_transcript(state.hello, hello_reply)

    valid = crypto.ed25519_verify(
        responder_signing_public_key,
        _signed_transcript(transcript, "RESPONDER"),
        signature,
    )

    if not valid:
        raise HandshakeError("Responder signature verification failed")

    initiator_signature = crypto.ed25519_sign(
        initiator_signing_private_key,
        _signed_transcript(transcript, "INITIATOR"),
    )

    auth = {
        "type": "AUTH",
        "version": PROTOCOL_VERSION,
        "session_id": state.session_id,
        "signature": initiator_signature.hex(),
    }

    session_keys = _derive_session_keys(
        private_key=state.private_key,
        peer_public_key=peer_public_key,
        initiator_mssv=state.initiator_mssv,
        responder_mssv=state.responder_mssv,
        group_mssvs=state.group_mssvs,
        transcript=transcript,
        session_id=state.session_id,
        role="initiator",
    )

    return auth, session_keys


# ---------------------------------------------------------------------
# Step 4: Responder verifies AUTH and derives session keys
# ---------------------------------------------------------------------

def verify_auth_and_derive_keys(
    state: ResponderState,
    auth: dict,
    initiator_signing_public_key: bytes,
) -> SessionKeys:
    """
    Responder:
        1. Validates AUTH.
        2. Verifies initiator's Ed25519 signature.
        3. Derives directional session keys.
    """

    _validate_message_type(auth, "AUTH")

    if auth.get("session_id") != state.session_id:
        raise HandshakeError("Session ID mismatch")

    signature = _require_hex(auth, "signature", 64)

    transcript = build_transcript(
        state.hello,
        state.hello_reply,
    )

    valid = crypto.ed25519_verify(
        initiator_signing_public_key,
        _signed_transcript(transcript, "INITIATOR"),
        signature,
    )

    if not valid:
        raise HandshakeError("Initiator signature verification failed")

    peer_public_key = _require_hex(
        state.hello, "dh_public_key", 32
    )

    return _derive_session_keys(
        private_key=state.private_key,
        peer_public_key=peer_public_key,
        initiator_mssv=state.initiator_mssv,
        responder_mssv=state.responder_mssv,
        group_mssvs=state.group_mssvs,
        transcript=transcript,
        session_id=state.session_id,
        role="responder",
    )
