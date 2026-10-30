"""
test_crypto_handshake.py - Unit tests cho crypto.py va handshake.py (vai tro C).

Dat file nay CUNG THU MUC voi crypto.py va handshake.py, roi chay:
    python -m pip install pytest cryptography
    python -m pytest -v

Thay MSSV mau trong MSSVS bang MSSV that cua nhom (giu dung thu tu).
"""

import hashlib
import os
import sys

import pytest
from cryptography.exceptions import InvalidTag

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import crypto
import handshake
from handshake import HandshakeError, Initiator, Responder

# ---- THAY bang MSSV that cua nhom, dung thu tu da thong nhat trong README ----
MSSVS = ["2412915", "2413675", "2412965"]


# =========================================================================== #
# Fixtures / helper
# =========================================================================== #
@pytest.fixture
def identities():
    a_priv, a_pub = crypto.generate_ed25519_keypair()
    b_priv, b_pub = crypto.generate_ed25519_keypair()
    return a_priv, a_pub, b_priv, b_pub


def run_handshake(identities, a_mssvs=MSSVS, b_mssvs=MSSVS):
    a_priv, a_pub, b_priv, b_pub = identities
    ini = Initiator(a_priv, b_pub, a_mssvs)
    res = Responder(b_priv, a_pub, b_mssvs)
    client_hello = ini.start()
    server_hello, b_keys = res.respond(client_hello)
    a_keys = ini.finish(server_hello)
    return a_keys, b_keys, client_hello, server_hello


def flip(data: bytes, index: int, bit: int = 0) -> bytes:
    b = bytearray(data)
    b[index] ^= 1 << bit
    return bytes(b)


# =========================================================================== #
# crypto.py - X25519 / HKDF
# =========================================================================== #
class TestX25519:
    def test_shared_secret_matches(self):
        a_priv, a_pub = crypto.generate_x25519_keypair()
        b_priv, b_pub = crypto.generate_x25519_keypair()
        assert crypto.x25519_shared_secret(a_priv, b_pub) == crypto.x25519_shared_secret(b_priv, a_pub)

    def test_public_key_is_32_bytes(self):
        _, pub = crypto.generate_x25519_keypair()
        assert len(pub) == 32

    def test_keypairs_are_unique(self):
        pubs = {crypto.generate_x25519_keypair()[1] for _ in range(50)}
        assert len(pubs) == 50

    @pytest.mark.parametrize("bad_len", [0, 31, 33, 64])
    def test_rejects_wrong_length_public_key(self, bad_len):
        priv, _ = crypto.generate_x25519_keypair()
        with pytest.raises(ValueError):
            crypto.x25519_shared_secret(priv, os.urandom(bad_len))

    def test_rfc7748_vector(self):
        # RFC 7748 section 6.1
        a_priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        b_pub = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        expected = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        priv = X25519PrivateKey.from_private_bytes(a_priv)
        assert crypto.x25519_shared_secret(priv, b_pub) == expected


class TestHKDF:
    def test_deterministic(self):
        s = os.urandom(32)
        assert crypto.derive_key(s, salt=b"salt") == crypto.derive_key(s, salt=b"salt")

    def test_output_length(self):
        assert len(crypto.derive_key(os.urandom(32), salt=b"s")) == 32
        assert len(crypto.derive_key(os.urandom(32), salt=b"s", length=64)) == 64

    def test_different_salt_changes_key(self):
        s = os.urandom(32)
        assert crypto.derive_key(s, salt=b"a") != crypto.derive_key(s, salt=b"b")

    def test_different_info_changes_key(self):
        s = os.urandom(32)
        assert crypto.derive_key(s, salt=b"a", info=b"x") != crypto.derive_key(s, salt=b"a", info=b"y")

    def test_empty_secret_rejected(self):
        with pytest.raises(ValueError):
            crypto.derive_key(b"", salt=b"s")

    @pytest.mark.parametrize("length", [0, -1, 255 * 32 + 1])
    def test_invalid_length_rejected(self, length):
        with pytest.raises(ValueError):
            crypto.derive_key(os.urandom(32), salt=b"s", length=length)

    def test_rfc5869_case1(self):
        # RFC 5869 test case 1 (SHA-256)
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        okm = HKDF(hashes.SHA256(), 42, salt, info).derive(ikm)
        assert okm.hex() == (
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )

    def test_directional_keys_distinct_and_32_bytes(self):
        k1, k2 = crypto.derive_directional_keys(os.urandom(32), salt=b"s")
        assert len(k1) == len(k2) == 32
        assert k1 != k2


# =========================================================================== #
# crypto.py - AES-256-GCM
# =========================================================================== #
class TestAESGCM:
    key = os.urandom(32)

    def test_roundtrip(self):
        nonce, ct = crypto.aes_gcm_encrypt(self.key, b"hello")
        assert crypto.aes_gcm_decrypt(self.key, nonce, ct) == b"hello"

    def test_roundtrip_unicode_vietnamese(self):
        msg = "Xin chào, tiếng Việt có dấu ✓".encode("utf-8")
        nonce, ct = crypto.aes_gcm_encrypt(self.key, msg)
        assert crypto.aes_gcm_decrypt(self.key, nonce, ct).decode("utf-8") == msg.decode("utf-8")

    def test_roundtrip_empty_plaintext(self):
        nonce, ct = crypto.aes_gcm_encrypt(self.key, b"")
        assert len(ct) == 16  # chi con tag
        assert crypto.aes_gcm_decrypt(self.key, nonce, ct) == b""

    def test_roundtrip_large(self):
        data = os.urandom(3 * 1024 * 1024)
        nonce, ct = crypto.aes_gcm_encrypt(self.key, data)
        assert crypto.aes_gcm_decrypt(self.key, nonce, ct) == data

    def test_ciphertext_differs_from_plaintext(self):
        _, ct = crypto.aes_gcm_encrypt(self.key, b"secret message")
        assert b"secret message" not in ct

    def test_nonce_length_12(self):
        nonce, _ = crypto.aes_gcm_encrypt(self.key, b"x")
        assert len(nonce) == 12

    def test_nonces_not_reused(self):
        nonces = {crypto.aes_gcm_encrypt(self.key, b"x")[0] for _ in range(5000)}
        assert len(nonces) == 5000

    def test_same_plaintext_gives_different_ciphertext(self):
        _, c1 = crypto.aes_gcm_encrypt(self.key, b"same")
        _, c2 = crypto.aes_gcm_encrypt(self.key, b"same")
        assert c1 != c2

    # ---- Bi sua doi: phai bi tu choi ----
    def test_tamper_ciphertext_body(self):
        nonce, ct = crypto.aes_gcm_encrypt(self.key, b"hello world")
        with pytest.raises(InvalidTag):
            crypto.aes_gcm_decrypt(self.key, nonce, flip(ct, 0))

    def test_tamper_tag(self):
        nonce, ct = crypto.aes_gcm_encrypt(self.key, b"hello world")
        with pytest.raises(InvalidTag):
            crypto.aes_gcm_decrypt(self.key, nonce, flip(ct, len(ct) - 1))

    def test_tamper_nonce(self):
        nonce, ct = crypto.aes_gcm_encrypt(self.key, b"hello world")
        with pytest.raises(InvalidTag):
            crypto.aes_gcm_decrypt(self.key, flip(nonce, 0), ct)

    def test_every_single_bit_flip_rejected(self):
        nonce, ct = crypto.aes_gcm_encrypt(self.key, b"short")
        for i in range(len(ct)):
            for bit in range(8):
                with pytest.raises(InvalidTag):
                    crypto.aes_gcm_decrypt(self.key, nonce, flip(ct, i, bit))

    def test_truncated_ciphertext(self):
        nonce, ct = crypto.aes_gcm_encrypt(self.key, b"hello world")
        with pytest.raises(InvalidTag):
            crypto.aes_gcm_decrypt(self.key, nonce, ct[:-1])

    def test_wrong_key(self):
        nonce, ct = crypto.aes_gcm_encrypt(self.key, b"hello")
        with pytest.raises(InvalidTag):
            crypto.aes_gcm_decrypt(os.urandom(32), nonce, ct)

    def test_aad_must_match(self):
        nonce, ct = crypto.aes_gcm_encrypt(self.key, b"chunk", aad=b"file1|0|5")
        assert crypto.aes_gcm_decrypt(self.key, nonce, ct, aad=b"file1|0|5") == b"chunk"
        with pytest.raises(InvalidTag):
            crypto.aes_gcm_decrypt(self.key, nonce, ct, aad=b"file1|1|5")
        with pytest.raises(InvalidTag):
            crypto.aes_gcm_decrypt(self.key, nonce, ct, aad=None)

    # ---- Tham so khong hop le ----
    @pytest.mark.parametrize("bad_len", [0, 16, 24, 31, 33])
    def test_rejects_bad_key_length(self, bad_len):
        with pytest.raises(ValueError):
            crypto.aes_gcm_encrypt(os.urandom(bad_len), b"x")
        with pytest.raises(ValueError):
            crypto.aes_gcm_decrypt(os.urandom(bad_len), os.urandom(12), b"x" * 20)

    @pytest.mark.parametrize("bad_len", [0, 8, 11, 13, 16])
    def test_rejects_bad_nonce_length(self, bad_len):
        with pytest.raises(ValueError):
            crypto.aes_gcm_decrypt(self.key, os.urandom(bad_len), b"x" * 20)

    def test_nist_gcm_vector_via_library(self):
        # Kiem chung AESGCM thu vien: McGrew-Viega test case 16 (AES-256, co AAD)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        iv = bytes.fromhex("cafebabefacedbaddecaf888")
        pt = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        )
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        expected_tag = bytes.fromhex("76fc6ece0f4e1768cddf8853bb2d551b")
        out = AESGCM(key).encrypt(iv, pt, aad)
        assert out[-16:] == expected_tag


# =========================================================================== #
# crypto.py - Ed25519
# =========================================================================== #
class TestEd25519:
    def test_sign_verify(self):
        priv, pub = crypto.generate_ed25519_keypair()
        sig = crypto.ed25519_sign(priv, b"msg")
        assert len(sig) == 64
        assert crypto.ed25519_verify(pub, b"msg", sig) is True

    def test_wrong_message(self):
        priv, pub = crypto.generate_ed25519_keypair()
        sig = crypto.ed25519_sign(priv, b"msg")
        assert crypto.ed25519_verify(pub, b"msG", sig) is False

    def test_wrong_key(self):
        priv, _ = crypto.generate_ed25519_keypair()
        _, other_pub = crypto.generate_ed25519_keypair()
        sig = crypto.ed25519_sign(priv, b"msg")
        assert crypto.ed25519_verify(other_pub, b"msg", sig) is False

    def test_tampered_signature(self):
        priv, pub = crypto.generate_ed25519_keypair()
        sig = crypto.ed25519_sign(priv, b"msg")
        assert crypto.ed25519_verify(pub, b"msg", flip(sig, 10)) is False

    def test_bad_signature_length_returns_false(self):
        _, pub = crypto.generate_ed25519_keypair()
        assert crypto.ed25519_verify(pub, b"msg", b"\x00" * 63) is False

    def test_bad_public_key_length_raises(self):
        with pytest.raises(ValueError):
            crypto.ed25519_verify(b"\x00" * 31, b"msg", b"\x00" * 64)


# =========================================================================== #
# crypto.py - SHA-256 / MSSV
# =========================================================================== #
class TestMSSV:
    def test_matches_assignment_formula(self):
        expected = hashlib.sha256("".join(MSSVS).encode("utf-8")).digest()
        assert crypto.hash_mssvs(MSSVS) == expected

    def test_known_value(self):
        # SHA256("2310001" + "2310002" + "2310003"): chi dung voi MSSV mau o tren
        if MSSVS == ["2310001", "2310002", "2310003"]:
            assert crypto.hash_mssvs(MSSVS).hex() == hashlib.sha256(b"231000123100022310003").hexdigest()

    def test_order_matters(self):
        assert crypto.hash_mssvs(["1", "2"]) != crypto.hash_mssvs(["2", "1"])

    def test_single_member(self):
        assert crypto.hash_mssvs(["2310001"]) == hashlib.sha256(b"2310001").digest()

    def test_digest_length(self):
        assert len(crypto.hash_mssvs(MSSVS)) == 32

    def test_empty_list_rejected(self):
        with pytest.raises(ValueError):
            crypto.hash_mssvs([])

    @pytest.mark.parametrize("bad", [[""], ["2310001", ""], [None], [123]])
    def test_invalid_members_rejected(self, bad):
        with pytest.raises(ValueError):
            crypto.hash_mssvs(bad)

    def test_hello_message_contains_all_mssv(self):
        # Chuoi bat tay theo de: "Hello, We are [MSSV_1], [MSSV_2], ..."
        # Neu nhom co ham tao chuoi nay, thay phan nay bang ham do.
        text = "Hello, We are " + ", ".join(MSSVS)
        assert text.startswith("Hello, We are ")
        for m in MSSVS:
            assert m in text


class TestHashHelpers:
    def test_sha256_bytes(self):
        assert crypto.sha256_bytes(b"abc").hex() == (
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )

    def test_sha256_file_matches_bytes(self, tmp_path):
        data = os.urandom(2 * 1024 * 1024 + 123)  # lon hon 1 khoi doc
        p = tmp_path / "f.bin"
        p.write_bytes(data)
        assert crypto.sha256_file(p) == hashlib.sha256(data).digest()

    def test_sha256_empty_file(self, tmp_path):
        p = tmp_path / "empty"
        p.write_bytes(b"")
        assert crypto.sha256_file(p) == hashlib.sha256(b"").digest()

    def test_hex_roundtrip(self):
        d = os.urandom(32)
        assert crypto.from_hex(crypto.to_hex(d)) == d

    def test_from_hex_invalid(self):
        with pytest.raises(ValueError):
            crypto.from_hex("zz")


# =========================================================================== #
# handshake.py - truong hop hop le
# =========================================================================== #
class TestHandshakeHappyPath:
    def test_keys_are_compatible(self, identities):
        a_keys, b_keys, *_ = run_handshake(identities)
        assert a_keys.send_key == b_keys.receive_key
        assert a_keys.receive_key == b_keys.send_key
        assert a_keys.transcript_hash == b_keys.transcript_hash

    def test_directional_keys_differ(self, identities):
        a_keys, *_ = run_handshake(identities)
        assert a_keys.send_key != a_keys.receive_key

    def test_key_confirmation_both_ways(self, identities):
        a_keys, b_keys, *_ = run_handshake(identities)
        b_keys.verify_confirmation(a_keys.make_confirmation())
        a_keys.verify_confirmation(b_keys.make_confirmation())

    def test_can_chat_after_handshake(self, identities):
        a_keys, b_keys, *_ = run_handshake(identities)
        nonce, ct = crypto.aes_gcm_encrypt(a_keys.send_key, "Chào B".encode("utf-8"))
        assert crypto.aes_gcm_decrypt(b_keys.receive_key, nonce, ct).decode("utf-8") == "Chào B"

    def test_hello_lengths(self, identities):
        _, _, ch, sh = run_handshake(identities)
        # Độ dài ClientHello và ServerHello phải bằng nhau
        assert len(ch) == len(sh)
        # Độ dài phải lớn hơn 130 vì đã cộng thêm chuỗi MSSV ("Hello, We are...")
        assert len(ch) > 130

    def test_each_session_has_fresh_keys(self, identities):
        k1, *_ = run_handshake(identities)
        k2, *_ = run_handshake(identities)
        assert k1.send_key != k2.send_key
        assert k1.transcript_hash != k2.transcript_hash

    def test_hello_fresh_ephemeral_keys(self, identities):
        _, _, ch1, _ = run_handshake(identities)
        _, _, ch2, _ = run_handshake(identities)
        
        # Dùng hàm parse của handshake để lấy chính xác trường ephemeral_public
        h1 = handshake.Hello.from_bytes(ch1, handshake.ROLE_INITIATOR)
        h2 = handshake.Hello.from_bytes(ch2, handshake.ROLE_INITIATOR)
        
        assert h1.ephemeral_public != h2.ephemeral_public

    def test_private_key_dropped_after_dh(self, identities):
        a_priv, a_pub, b_priv, b_pub = identities
        ini = Initiator(a_priv, b_pub, MSSVS)
        res = Responder(b_priv, a_pub, MSSVS)
        sh, _ = res.respond(ini.start())
        ini.finish(sh)
        assert ini._eph_private is None
        assert res._eph_private is None

    def test_session_keys_repr_hides_keys(self, identities):
        a_keys, *_ = run_handshake(identities)
        assert a_keys.send_key.hex() not in repr(a_keys)
        assert a_keys.receive_key.hex() not in repr(a_keys)


# =========================================================================== #
# handshake.py - cau hinh sai
# =========================================================================== #
class TestHandshakeMisconfiguration:
    def test_mssv_mismatch_fails(self, identities):
        with pytest.raises(HandshakeError):
            run_handshake(identities, a_mssvs=MSSVS, b_mssvs=["9999999", "8888888"])

    def test_mssv_order_mismatch_fails(self, identities):
        with pytest.raises(HandshakeError):
            run_handshake(identities, a_mssvs=MSSVS, b_mssvs=list(reversed(MSSVS)))

    def test_wrong_pinned_key_for_peer(self, identities):
        a_priv, a_pub, b_priv, b_pub = identities
        _, wrong_pub = crypto.generate_ed25519_keypair()
        ini = Initiator(a_priv, b_pub, MSSVS)
        res = Responder(b_priv, wrong_pub, MSSVS)  # B pin sai khoa cua A
        with pytest.raises(HandshakeError):
            res.respond(ini.start())

    def test_initiator_pins_wrong_responder_key(self, identities):
        a_priv, a_pub, b_priv, b_pub = identities
        _, wrong_pub = crypto.generate_ed25519_keypair()
        ini = Initiator(a_priv, wrong_pub, MSSVS)  # A pin sai khoa cua B
        res = Responder(b_priv, a_pub, MSSVS)
        sh, _ = res.respond(ini.start())
        with pytest.raises(HandshakeError):
            ini.finish(sh)

    @pytest.mark.parametrize("n", [0, 31, 33])
    def test_pinned_key_length_checked(self, identities, n):
        a_priv, *_ = identities
        with pytest.raises(ValueError):
            Initiator(a_priv, os.urandom(n), MSSVS)

    def test_empty_mssv_list_rejected(self, identities):
        a_priv, _, _, b_pub = identities
        with pytest.raises(ValueError):
            Initiator(a_priv, b_pub, [])


# =========================================================================== #
# handshake.py - tan cong / sua doi (nen tang cho kich ban MitM ngay 8-9)
# =========================================================================== #
class TestHandshakeTampering:
    def _setup(self, identities):
        a_priv, a_pub, b_priv, b_pub = identities
        ini = Initiator(a_priv, b_pub, MSSVS)
        res = Responder(b_priv, a_pub, MSSVS)
        return ini, res

    @pytest.mark.parametrize("index", [0, 1, 2, 33, 34, 65, 66, 100, 129])
    def test_tampered_client_hello_rejected(self, identities, index):
        ini, res = self._setup(identities)
        ch = ini.start()
        with pytest.raises(HandshakeError):
            res.respond(flip(ch, index))

    @pytest.mark.parametrize("index", [0, 1, 2, 33, 34, 65, 66, 100, 129])
    def test_tampered_server_hello_rejected(self, identities, index):
        ini, res = self._setup(identities)
        sh, _ = res.respond(ini.start())
        with pytest.raises(HandshakeError):
            ini.finish(flip(sh, index))

    def test_mitm_replaces_ephemeral_key_in_client_hello(self, identities):
        """Mallory thay khoa X25519 cua A bang khoa cua Mallory -> B phai tu choi."""
        ini, res = self._setup(identities)
        ch = ini.start()
        
        h = handshake.Hello.from_bytes(ch, handshake.ROLE_INITIATOR)
        _, mallory_eph = crypto.generate_x25519_keypair()
        forged_h = handshake.Hello(h.role, h.hello_str, mallory_eph, h.nonce, h.signature)
        
        with pytest.raises(HandshakeError):
            res.respond(forged_h.to_bytes())

    def test_mitm_replaces_ephemeral_key_in_server_hello(self, identities):
        ini, res = self._setup(identities)
        sh, _ = res.respond(ini.start())
        
        h = handshake.Hello.from_bytes(sh, handshake.ROLE_RESPONDER)
        _, mallory_eph = crypto.generate_x25519_keypair()
        forged_h = handshake.Hello(h.role, h.hello_str, mallory_eph, h.nonce, h.signature)
        
        with pytest.raises(HandshakeError):
            ini.finish(forged_h.to_bytes())

    def test_mitm_with_own_identity_key_rejected(self, identities):
        """Mallory ky Hello bang khoa Ed25519 cua rieng Mallory (khong duoc pin)."""
        a_priv, a_pub, b_priv, b_pub = identities
        m_priv, m_pub = crypto.generate_ed25519_keypair()
        # Mallory gia lam A gui cho B
        fake_a = Initiator(m_priv, b_pub, MSSVS)
        res = Responder(b_priv, a_pub, MSSVS)
        with pytest.raises(HandshakeError):
            res.respond(fake_a.start())
        # Mallory gia lam B tra loi A
        ini = Initiator(a_priv, b_pub, MSSVS)
        ini.start()
        fake_b = Responder(m_priv, a_pub, MSSVS)
        # fake_b can ClientHello hop le tu A, nhung ky bang khoa Mallory
        ini2 = Initiator(a_priv, m_pub, MSSVS)
        sh, _ = fake_b.respond(ini2.start())
        ini3 = Initiator(a_priv, b_pub, MSSVS)
        ini3.start()
        with pytest.raises(HandshakeError):
            ini3.finish(sh)

    def test_server_hello_replayed_from_other_session_rejected(self, identities):
        """ServerHello cu khong duoc chap nhan cho phien moi (chu ky rang buoc ClientHello)."""
        a_priv, a_pub, b_priv, b_pub = identities
        ini1 = Initiator(a_priv, b_pub, MSSVS)
        res1 = Responder(b_priv, a_pub, MSSVS)
        old_sh, _ = res1.respond(ini1.start())
        ini2 = Initiator(a_priv, b_pub, MSSVS)
        ini2.start()
        with pytest.raises(HandshakeError):
            ini2.finish(old_sh)

    def test_client_hello_reflected_as_server_hello_rejected(self, identities):
        ini, _ = self._setup(identities)
        ch = ini.start()
        with pytest.raises(HandshakeError):
            ini.finish(ch)  # sai role

    def test_wrong_version_rejected(self, identities):
        ini, res = self._setup(identities)
        ch = bytearray(ini.start())
        ch[0] = 99
        with pytest.raises(HandshakeError):
            res.respond(bytes(ch))

    def test_wrong_role_rejected(self, identities):
        ini, res = self._setup(identities)
        ch = bytearray(ini.start())
        ch[1] = handshake.ROLE_RESPONDER
        with pytest.raises(HandshakeError):
            res.respond(bytes(ch))

    @pytest.mark.parametrize("n", [0, 1, 129, 131, 500])
    def test_wrong_length_hello_rejected(self, identities, n):
        _, res = self._setup(identities)
        with pytest.raises(HandshakeError):
            res.respond(os.urandom(n))

    def test_low_order_point_rejected(self, identities):
        """Khoa cong khai bac thap (toan 0) cho bi mat DH toan 0 -> phai bi tu choi."""
        a_priv, a_pub, b_priv, b_pub = identities
        res = Responder(b_priv, a_pub, MSSVS)
        # Mallory khong co khoa ky cua A, nen kiem tra truc tiep ham _dh
        with pytest.raises(HandshakeError):
            res._dh(bytes(32))

    def test_handshake_objects_single_use(self, identities):
        a_priv, a_pub, b_priv, b_pub = identities
        ini = Initiator(a_priv, b_pub, MSSVS)
        res = Responder(b_priv, a_pub, MSSVS)
        ch = ini.start()
        res.respond(ch)
        with pytest.raises(HandshakeError):
            res.respond(ch)

    def test_start_twice_rejected(self, identities):
        a_priv, _, _, b_pub = identities
        ini = Initiator(a_priv, b_pub, MSSVS)
        ini.start()
        with pytest.raises(HandshakeError):
            ini.start()

    def test_finish_before_start_rejected(self, identities):
        a_priv, _, _, b_pub = identities
        ini = Initiator(a_priv, b_pub, MSSVS)
        with pytest.raises(HandshakeError):
            ini.finish(b"\x00" * 130)


# =========================================================================== #
# handshake.py - xac nhan khoa (key confirmation)
# =========================================================================== #
class TestKeyConfirmation:
    def test_tampered_confirmation_rejected(self, identities):
        a_keys, b_keys, *_ = run_handshake(identities)
        blob = a_keys.make_confirmation()
        for idx in (0, 12, len(blob) - 1):
            with pytest.raises(HandshakeError):
                b_keys.verify_confirmation(flip(blob, idx))

    def test_too_short_confirmation_rejected(self, identities):
        _, b_keys, *_ = run_handshake(identities)
        with pytest.raises(HandshakeError):
            b_keys.verify_confirmation(b"\x00" * 12)

    def test_confirmation_from_other_session_rejected(self, identities):
        a1, *_ = run_handshake(identities)
        _, b2, *_ = run_handshake(identities)
        with pytest.raises(HandshakeError):
            b2.verify_confirmation(a1.make_confirmation())

    def test_reflection_attack_rejected(self, identities):
        """A gui lai chinh goi xac nhan cua minh cho minh -> phai bi tu choi (key rieng tung chieu)."""
        a_keys, *_ = run_handshake(identities)
        with pytest.raises(HandshakeError):
            a_keys.verify_confirmation(a_keys.make_confirmation())

    def test_cross_direction_decrypt_fails(self, identities):
        """Tin A->B khong giai ma duoc bang khoa chieu B->A."""
        a_keys, b_keys, *_ = run_handshake(identities)
        nonce, ct = crypto.aes_gcm_encrypt(a_keys.send_key, b"hi")
        with pytest.raises(InvalidTag):
            crypto.aes_gcm_decrypt(b_keys.send_key, nonce, ct)
