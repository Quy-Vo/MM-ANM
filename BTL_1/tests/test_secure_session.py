"""Unit test cho SecureSession: counter, replay, đảo thứ tự, sửa đổi."""
import pytest

import crypto
import handshake
from handshake import Initiator, Responder
from secure_session import SecureSession, SessionError

MSSVS = ["2412915", "2413675", "2412965"]


@pytest.fixture
def pair():
    a_priv, a_pub = crypto.generate_ed25519_keypair()
    b_priv, b_pub = crypto.generate_ed25519_keypair()
    ini, res = Initiator(a_priv, b_pub, MSSVS), Responder(b_priv, a_pub, MSSVS)
    sh, b_keys = res.respond(ini.start())
    a_keys = ini.finish(sh)
    return SecureSession(a_keys), SecureSession(b_keys)


def test_roundtrip(pair):
    a, b = pair
    hdr, ct = a.encrypt(b"hello", b"chat")
    assert b.decrypt(hdr, ct, b"chat") == b"hello"


def test_counter_increases(pair):
    a, _ = pair
    counters = [int(a.encrypt(b"x", b"chat")[0].split(":")[0]) for _ in range(5)]
    assert counters == [0, 1, 2, 3, 4]


def test_replay_rejected(pair):
    a, b = pair
    hdr, ct = a.encrypt(b"pay 100", b"chat")
    assert b.decrypt(hdr, ct, b"chat") == b"pay 100"
    with pytest.raises(SessionError):
        b.decrypt(hdr, ct, b"chat")


def test_reorder_rejected(pair):
    a, b = pair
    h1, c1 = a.encrypt(b"first", b"chat")
    h2, c2 = a.encrypt(b"second", b"chat")
    assert b.decrypt(h2, c2, b"chat") == b"second"
    with pytest.raises(SessionError):
        b.decrypt(h1, c1, b"chat")


def test_tampered_ct_rejected_and_counter_not_consumed(pair):
    a, b = pair
    hdr, ct = a.encrypt(b"hello", b"chat")
    bad = bytes([ct[0] ^ 1]) + ct[1:]
    with pytest.raises(SessionError):
        b.decrypt(hdr, bad, b"chat")
    assert b.decrypt(hdr, ct, b"chat") == b"hello"   # gói thật vẫn nhận được


def test_counter_in_header_cannot_be_forged(pair):
    a, b = pair
    hdr, ct = a.encrypt(b"hello", b"chat")
    _, nonce = hdr.split(":")
    with pytest.raises(SessionError):
        b.decrypt(f"7:{nonce}", ct, b"chat")        # đổi counter -> AAD khác -> sai xác thực


def test_aad_mismatch_rejected(pair):
    a, b = pair
    hdr, ct = a.encrypt(b"hello", b"chat")
    with pytest.raises(SessionError):
        b.decrypt(hdr, ct, b"file_end:abc")


def test_reflection_rejected(pair):
    a, _ = pair
    hdr, ct = a.encrypt(b"hello", b"chat")
    with pytest.raises(SessionError):
        a.decrypt(hdr, ct, b"chat")                  # khóa hai chiều khác nhau


@pytest.mark.parametrize("bad", ["", "abc", "1:zz", "-1:" + "0" * 24, "1:" + "0" * 23, None, 5, "1:" + "G" * 24])
def test_malformed_header_rejected(pair, bad):
    _, b = pair
    with pytest.raises(SessionError):
        b.decrypt(bad, b"x" * 32, b"chat")
