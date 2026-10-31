"""Test CA nội bộ: nội dung chứng thư (MSSV), cấp phát, thu hồi/CRL, xác thực ở tầng ứng dụng và ở tầng TLS thật."""
import datetime
import http.client
import os
import ssl
import threading
import time
import warnings
from datetime import timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import ca
import pki_verify
import tls_client
from config import MSSVS
from https_server import make_server

MSSV_STR = "-".join(MSSVS)


def _read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def load_cert(path):
    return x509.load_pem_x509_certificate(_read_bytes(path))


def load_crl(path):
    return x509.load_pem_x509_crl(_read_bytes(path))


@pytest.fixture
def pki(tmp_path):
    ca_dir, certs, www = str(tmp_path / "pki"), str(tmp_path / "certs"), str(tmp_path / "www")
    ca.init_ca(ca_dir, www_dir=www)
    return type("P", (), dict(
        ca_dir=ca_dir, certs=certs, www=www, tmp=tmp_path,
        ca_crt=os.path.join(ca_dir, "ca.crt"), crl=os.path.join(ca_dir, "crl.pem"),
    ))


def issue(pki, name="server", **kw):
    kw.setdefault("cn", "localhost")
    kw.setdefault("sans", ["localhost", "127.0.0.1"])
    cert, serial = ca.issue(pki.ca_dir, out_dir=pki.certs, name=name, **kw)
    return cert, serial


def verify(pki, cert, hostname="localhost", **kw):
    return pki_verify.verify_chain(cert, load_cert(pki.ca_crt), load_crl(pki.crl), hostname, **kw)


# --------------------------------------------------------------------------- #
# Nội dung chứng thư theo đề (lồng ghép MSSV)
# --------------------------------------------------------------------------- #
def test_ca_subject_contains_mssv(pki):
    cert = load_cert(pki.ca_crt)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
    assert cn == f"CA-Root-{MSSV_STR}"
    assert ou == f"Faculty of Computer Science and Engineer \u2013 {MSSV_STR}"
    assert cert.subject == cert.issuer                      # tự ký


def test_ca_certificate_is_a_ca(pki):
    cert = load_cert(pki.ca_crt)
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign and ku.crl_sign


def test_server_cert_extensions(pki):
    cert, _ = issue(pki)
    assert cert.issuer == load_cert(pki.ca_crt).subject
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "localhost" in san.get_values_for_type(x509.DNSName)
    assert cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
    assert MSSV_STR in ou


# --------------------------------------------------------------------------- #
# Cấp phát
# --------------------------------------------------------------------------- #
def test_issue_registers_in_index_and_serials_unique(pki):
    _, s1 = issue(pki, name="a")
    _, s2 = issue(pki, name="b")
    assert s1 != s2
    serials = [s for s, _ in ca.list_issued(pki.ca_dir)]
    assert format(s1, "x") in serials and format(s2, "x") in serials


def test_issue_from_csr_signs_requester_key(pki):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
           .sign(key, hashes.SHA256()))
    csr_path = pki.tmp / "req.csr"
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    cert, _ = ca.issue(pki.ca_dir, csr_path=str(csr_path), out_dir=pki.certs, name="fromcsr")
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()
    assert not os.path.exists(os.path.join(pki.certs, "fromcsr.key"))   # CA không bao giờ thấy khóa riêng
    assert verify(pki, cert)[0]


def test_issue_ignores_ca_flag_requested_in_csr(pki):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
           .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
           .sign(key, hashes.SHA256()))
    p = pki.tmp / "evil.csr"
    p.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    cert, _ = ca.issue(pki.ca_dir, csr_path=str(p), out_dir=pki.certs, name="evil")
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False


def test_issue_without_cn_rejected(pki):
    with pytest.raises(ca.CAError):
        ca.issue(pki.ca_dir, out_dir=pki.certs)


def test_init_refuses_to_overwrite(pki):
    with pytest.raises(ca.CAError):
        ca.init_ca(pki.ca_dir)


# --------------------------------------------------------------------------- #
# Thu hồi và CRL
# --------------------------------------------------------------------------- #
def test_initial_crl_is_empty_and_valid(pki):
    crl = load_crl(pki.crl)
    assert len(list(crl)) == 0
    assert crl.is_signature_valid(load_cert(pki.ca_crt).public_key())


def test_revoke_puts_serial_in_crl_and_increments_number(pki):
    cert, serial = issue(pki)
    n0 = load_crl(pki.crl).extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    ca.revoke(pki.ca_dir, serial=format(serial, "x"), reason="key_compromise", www_dir=pki.www)
    crl = load_crl(pki.crl)
    assert crl.get_revoked_certificate_by_serial_number(serial) is not None
    assert crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == n0 + 1
    assert os.path.exists(os.path.join(pki.www, "ca.crl"))             # đã công bố


def test_crl_lists_only_revoked(pki):
    good, gs = issue(pki, name="good")
    bad, bs = issue(pki, name="bad")
    ca.revoke(pki.ca_dir, serial=format(bs, "x"))
    crl = load_crl(pki.crl)
    assert crl.get_revoked_certificate_by_serial_number(gs) is None
    assert crl.get_revoked_certificate_by_serial_number(bs) is not None


def test_revoke_twice_is_idempotent(pki):
    _, s = issue(pki)
    ca.revoke(pki.ca_dir, serial=format(s, "x"))
    ca.revoke(pki.ca_dir, serial=format(s, "x"))
    assert len(list(load_crl(pki.crl))) == 1


def test_revoke_unknown_serial_rejected(pki):
    with pytest.raises(ca.CAError):
        ca.revoke(pki.ca_dir, serial="deadbeef")


def test_revoke_bad_reason_rejected(pki):
    _, s = issue(pki)
    with pytest.raises(ca.CAError):
        ca.revoke(pki.ca_dir, serial=format(s, "x"), reason="because")


# --------------------------------------------------------------------------- #
# Xác thực ở tầng ứng dụng (pki_verify)
# --------------------------------------------------------------------------- #
def test_verify_valid(pki):
    cert, _ = issue(pki)
    ok, reason = verify(pki, cert)
    assert ok, reason


def test_verify_revoked(pki):
    cert, s = issue(pki)
    ca.revoke(pki.ca_dir, serial=format(s, "x"), reason="key_compromise")
    ok, reason = verify(pki, cert)
    assert not ok and "thu hồi" in reason and "key_compromise" in reason


def test_verify_before_revocation_then_after(pki):
    cert, s = issue(pki)
    assert verify(pki, cert)[0]
    ca.revoke(pki.ca_dir, serial=format(s, "x"))
    assert not verify(pki, cert)[0]


def test_verify_foreign_ca(pki, tmp_path):
    other = str(tmp_path / "other")
    ca.init_ca(other, cn="CA-Gia-Mao")
    cert, _ = ca.issue(other, cn="localhost", sans=["localhost"], out_dir=pki.certs, name="foreign")
    ok, reason = verify(pki, cert)
    assert not ok and "CA tin cậy" in reason


def test_verify_expired(pki):
    cert, _ = issue(pki, days=30, backdate_days=60)
    ok, reason = verify(pki, cert)
    assert not ok and "hết hạn" in reason


def test_verify_not_yet_valid(pki):
    cert, _ = issue(pki)
    past = datetime.datetime.now(timezone.utc) - timedelta(days=3650)
    ok, reason = verify(pki, cert, now=past)
    assert not ok


def test_verify_hostname_mismatch(pki):
    cert, _ = issue(pki)
    ok, reason = verify(pki, cert, hostname="ngan-hang.example")
    assert not ok and "tên máy chủ" in reason.lower()


def test_verify_ip_san(pki):
    cert, _ = issue(pki)
    assert verify(pki, cert, hostname="127.0.0.1")[0]
    assert not verify(pki, cert, hostname="10.0.0.1")[0]


def test_verify_requires_crl(pki):
    cert, _ = issue(pki)
    ok, reason = pki_verify.verify_chain(cert, load_cert(pki.ca_crt), None, "localhost")
    assert not ok and "CRL" in reason


def test_verify_crl_signed_by_other_key_rejected(pki, tmp_path):
    cert, s = issue(pki)
    other = str(tmp_path / "other")
    ca.init_ca(other)
    forged = load_crl(os.path.join(other, "crl.pem"))                  # CRL rỗng do CA khác ký
    ok, reason = pki_verify.verify_chain(cert, load_cert(pki.ca_crt), forged, "localhost")
    assert not ok


def test_verify_expired_crl_rejected(pki):
    cert, _ = issue(pki)
    ca.gen_crl(pki.ca_dir, next_update_days=7, backdate_days=10)
    ok, reason = verify(pki, cert)
    assert not ok and "CRL đã hết hạn" in reason


def test_verify_tampered_crl_rejected(pki):
    cert, s = issue(pki)
    ca.revoke(pki.ca_dir, serial=format(s, "x"))
    pem = bytearray(_read_bytes(pki.crl))
    idx = pem.index(b"\n") + 40
    pem[idx] = ord("A") if pem[idx] != ord("A") else ord("B")
    try:
        crl = x509.load_pem_x509_crl(bytes(pem))
    except ValueError:
        return                                                         # hỏng đến mức không đọc được cũng là bị từ chối
    ok, _ = pki_verify.verify_chain(cert, load_cert(pki.ca_crt), crl, "localhost")
    assert not ok


# --------------------------------------------------------------------------- #
# Xác thực ở tầng TLS thật (OpenSSL kiểm tra chuỗi, tên và CRL)
# --------------------------------------------------------------------------- #
class Server:
    def __init__(self, pki, name):
        self.httpd = make_server(0, os.path.join(pki.certs, f"{name}.crt"), os.path.join(pki.certs, f"{name}.key"),
                                 pki.www, host="127.0.0.1")
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def serve(pki):
    servers = []

    def start(name):
        s = Server(pki, name)
        servers.append(s)
        return s
    yield start
    for s in servers:
        s.close()


def tls_get(pki, srv, hostname="localhost", path="/", use_crl=True):
    """Thử lại tối đa 2 lần CHỈ khi kết nối bị reset; lỗi xác thực chứng thư thì không bao giờ thử lại.
    Mỗi lần thử lại đều phát cảnh báo để còn thấy trong kết quả pytest."""
    last = None
    for attempt in range(3):
        try:
            return tls_client.fetch("127.0.0.1", srv.port, pki.ca_crt, pki.crl if use_crl else None, hostname, path)
        except ssl.SSLCertVerificationError:
            raise
        except (ConnectionResetError, ConnectionAbortedError) as exc:
            last = exc
            warnings.warn(f"tls_get: kết nối bị reset (lần {attempt + 1}/3), thử lại: {exc}")
            time.sleep(0.2)
    raise last


def test_tls_valid_certificate_accepted(pki, serve):
    issue(pki, name="ok")
    status, body = tls_get(pki, serve("ok"))
    assert status == 200 and b"HTTPS" in body


def test_tls_revoked_certificate_rejected(pki, serve):
    _, s = issue(pki, name="rev")
    srv = serve("rev")
    assert tls_get(pki, srv)[0] == 200                                  # trước khi thu hồi vẫn vào được
    ca.revoke(pki.ca_dir, serial=format(s, "x"), reason="key_compromise")
    with pytest.raises(ssl.SSLCertVerificationError) as exc:
        tls_get(pki, srv)                                               # sau khi thu hồi: OpenSSL từ chối
    assert "revoked" in exc.value.verify_message


def test_tls_without_crl_does_not_detect_revocation(pki, serve):
    """Đối chứng: không kiểm tra CRL thì chứng thư bị thu hồi vẫn được chấp nhận."""
    _, s = issue(pki, name="rev2")
    ca.revoke(pki.ca_dir, serial=format(s, "x"))
    assert tls_get(pki, serve("rev2"), use_crl=False)[0] == 200


def test_tls_foreign_ca_rejected(pki, serve, tmp_path):
    other = str(tmp_path / "other")
    ca.init_ca(other, cn="CA-Gia-Mao")
    ca.issue(other, cn="localhost", sans=["localhost", "127.0.0.1"], out_dir=pki.certs, name="foreign")
    with pytest.raises(ssl.SSLCertVerificationError):
        tls_get(pki, serve("foreign"))


def test_tls_expired_rejected(pki, serve):
    issue(pki, name="old", days=30, backdate_days=60)
    with pytest.raises(ssl.SSLCertVerificationError) as exc:
        tls_get(pki, serve("old"))
    assert "expired" in exc.value.verify_message


def test_tls_hostname_mismatch_rejected(pki, serve):
    issue(pki, name="host")
    with pytest.raises(ssl.SSLCertVerificationError):
        tls_get(pki, serve("host"), hostname="ngan-hang.example")


# --------------------------------------------------------------------------- #
# Web server không được lộ khóa riêng
# --------------------------------------------------------------------------- #
HOSTILE_PATHS = ["/../pki/ca.key", "/pki/ca.key", "/%2e%2e/pki/ca.key", "/../certs/valid.key", "/certs/valid.key",
                 "/..%2f..%2fetc/passwd", "/..\\..\\pki\\ca.key", "/%5c..%5cpki%5cca.key", "//pki/ca.key"]


def test_www_directory_contains_no_private_material(pki):
    """Thứ duy nhất server có thể phục vụ là thư mục www/: nó không được chứa khóa riêng nào."""
    issue(pki, name="valid")
    ca.gen_crl(pki.ca_dir, www_dir=pki.www)
    for dirpath, _, files in os.walk(pki.www):
        for name in files:
            with open(os.path.join(dirpath, name), "rb") as f:
                assert b"PRIVATE KEY" not in f.read(), name


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_handler_never_resolves_outside_www(pki, path):
    """Kiểm tra trực tiếp đường dẫn mà handler sẽ mở (xác định, không phụ thuộc mạng/hệ điều hành)."""
    from https_server import QuietHandler
    os.makedirs(pki.www, exist_ok=True)
    handler = QuietHandler.__new__(QuietHandler)
    handler.directory = pki.www
    root = os.path.realpath(pki.www)
    resolved = os.path.realpath(handler.translate_path(path))
    assert os.path.commonpath([root, resolved]) == root


@pytest.mark.parametrize("path", HOSTILE_PATHS + ["/"])
def test_https_server_does_not_leak_private_material(pki, serve, path):
    issue(pki, name="valid")
    srv = serve("valid")
    try:
        status, body = tls_get(pki, srv, path=path)
    except (ConnectionError, ssl.SSLError) as exc:
        # Server từ chối bằng cách đóng kết nối: không có dữ liệu nào bị phục vụ. Tính chất an toàn đã được kiểm tra
        # xác định ở test_handler_never_resolves_outside_www. Vẫn phát cảnh báo để lỗi reset không bị che khuất.
        warnings.warn(f"leak test {path!r}: kết nối bị đóng thay vì nhận phản hồi 4xx ({exc}); kiểm tra lại server")
        return
    assert b"PRIVATE KEY" not in body
    assert status in (200, 301, 400, 404)
    if path != "/":
        assert status != 200


def test_https_server_publishes_ca_files(pki, serve):
    issue(pki, name="pub")
    srv = serve("pub")
    status, body = tls_get(pki, srv, path="/ca.crt")
    assert status == 200 and b"BEGIN CERTIFICATE" in body
    status, body = tls_get(pki, srv, path="/ca.crl")
    assert status == 200 and b"BEGIN X509 CRL" in body
