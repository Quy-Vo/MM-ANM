"""
tls_client.py — Client HTTPS xác thực chứng thư máy chủ bằng CA nội bộ VÀ kiểm tra thu hồi (CRL) ở tầng TLS.

python tls_client.py --port 4443 --ca certs/ca.crt --crl pki/crl.pem --hostname localhost
"""
import argparse
import http.client
import os
import ssl
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import serialization


def make_context(ca_file: str, crl_file: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_file)      # bắt buộc xác minh chuỗi + tên máy chủ
    if crl_file:
        ctx.load_verify_locations(cafile=crl_file)         # nạp CRL vào kho xác minh của OpenSSL
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF      # thiếu CRL hoặc chứng thư bị thu hồi -> từ chối
    return ctx


def fetch(host: str, port: int, ca_file: str, crl_file: str | None, server_hostname: str, path: str = "/", timeout: float = 5):
    """Trả về (status, body). Ném ssl.SSLError nếu xác thực chứng thư thất bại."""
    ctx = make_context(ca_file, crl_file)
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
    conn.connect = _connect_with_sni(conn, ctx, server_hostname, timeout)
    try:
        conn.request("GET", path, headers={"Host": server_hostname})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _connect_with_sni(conn, ctx, server_hostname, timeout):
    import socket

    def connect():
        sock = socket.create_connection((conn.host, conn.port), timeout)
        conn.sock = ctx.wrap_socket(sock, server_hostname=server_hostname)
    return connect


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4443)
    ap.add_argument("--ca", default="certs/ca.crt")
    ap.add_argument("--crl", default="pki/crl.pem")
    ap.add_argument("--hostname", default="localhost")
    ap.add_argument("--no-crl", action="store_true")
    a = ap.parse_args()
    try:
        status, _ = fetch(a.host, a.port, a.ca, None if a.no_crl else a.crl, a.hostname)
        print(f"[TLS] THÀNH CÔNG: chứng thư hợp lệ, HTTP {status}")
    except ssl.SSLCertVerificationError as exc:
        print(f"[TLS] TỪ CHỐI: {exc.verify_message}")
    except (ssl.SSLError, OSError) as exc:
        print(f"[TLS] LỖI: {exc}")


if __name__ == "__main__":
    main()
