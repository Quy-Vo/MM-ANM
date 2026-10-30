"""Unit test for the cryptographic handshake and AES-GCM tamper detection."""
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "srcs"
sys.path.insert(0, str(SRC))

import crypto
import handshake
from cryptography.exceptions import InvalidTag


def main():
    initiator_private, initiator_public = crypto.generate_ed25519_keypair()
    responder_private, responder_public = crypto.generate_ed25519_keypair()

    initiator_state, hello = handshake.create_hello("MSSV_A", "MSSV_B")
    responder_state, reply = handshake.accept_hello(hello, responder_private)
    auth, initiator_keys = handshake.verify_reply_and_create_auth(
        initiator_state, reply, responder_public, initiator_private
    )
    responder_keys = handshake.verify_auth_and_derive_keys(
        responder_state, auth, initiator_public
    )

    assert initiator_keys.session_id == responder_keys.session_id
    assert initiator_keys.send_key == responder_keys.receive_key
    assert initiator_keys.receive_key == responder_keys.send_key

    nonce, ciphertext = crypto.aes_gcm_encrypt(
        initiator_keys.send_key, b"hello", aad=b"test-aad"
    )
    assert crypto.aes_gcm_decrypt(
        responder_keys.receive_key, nonce, ciphertext, aad=b"test-aad"
    ) == b"hello"

    tampered = bytearray(ciphertext)
    tampered[0] ^= 1
    try:
        crypto.aes_gcm_decrypt(
            responder_keys.receive_key, nonce, bytes(tampered), aad=b"test-aad"
        )
    except InvalidTag:
        pass
    else:
        raise AssertionError("AES-GCM accepted modified ciphertext")

    print("PASS: handshake, matching directional keys, AES-GCM, tamper rejection")


if __name__ == "__main__":
    main()
