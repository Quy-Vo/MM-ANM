"""
pki_demo.py — Kịch bản thử nghiệm xác thực chứng thư (chạy tự động, tạo bằng chứng cho báo cáo).

python pki_demo.py
Dựng CA thật trong thư mục tạm, cấp các chứng thư khác nhau, chạy HTTPS thật và kiểm tra bằng cả hai cách:
  (a) verify_chain()  — xác thực ở tầng ứng dụng (pki_verify.py)
  (b) TLS client      — OpenSSL xác thực chuỗi, tên máy chủ và CRL ở tầng TLS (tls_client.py)
"""
import os
import ssl
import tempfile
import threading

from cryptography import x509

import ca
import pki_verify
import tls_client
from https_server import make_server


def _load(path):
    with open(path, "rb") as f:
        data = f.read()
    return data


def main() -> int:
    root = tempfile.mkdtemp(prefix="pki_demo_")
    ca_dir, other_dir, certs = os.path.join(root, "pki"), os.path.join(root, "other"), os.path.join(root, "certs")
    www = os.path.join(root, "www")
    ca.init_ca(ca_dir, www_dir=www)
    ca.init_ca(other_dir, cn="CA-Gia-Mao")
    ok_cert, ok_serial = ca.issue(ca_dir, cn="localhost", sans=["localhost", "127.0.0.1"], out_dir=certs, name="valid")
    ca.issue(ca_dir, cn="localhost", sans=["localhost", "127.0.0.1"], out_dir=certs, name="revoked")
    ca.issue(ca_dir, cn="localhost", sans=["localhost", "127.0.0.1"], out_dir=certs, name="expired", days=30, backdate_days=60)
    ca.issue(other_dir, cn="localhost", sans=["localhost", "127.0.0.1"], out_dir=certs, name="foreign")
    revoked_serial = x509.load_pem_x509_certificate(_load(os.path.join(certs, "revoked.crt"))).serial_number
    ca.revoke(ca_dir, serial=format(revoked_serial, "x"), reason="key_compromise", www_dir=www)

    ca_crt, crl_pem = os.path.join(ca_dir, "ca.crt"), os.path.join(ca_dir, "crl.pem")
    ca_cert = x509.load_pem_x509_certificate(_load(ca_crt))
    crl = x509.load_pem_x509_crl(_load(crl_pem))

    scenarios = [
        ("1. Chứng thư hợp lệ", "valid", "localhost", "THÀNH CÔNG"),
        ("2. Chứng thư đã bị thu hồi (CRL)", "revoked", "localhost", "TỪ CHỐI"),
        ("3. Chứng thư do CA lạ cấp", "foreign", "localhost", "TỪ CHỐI"),
        ("4. Chứng thư đã hết hạn", "expired", "localhost", "TỪ CHỐI"),
        ("5. Sai tên máy chủ", "valid", "ngan-hang.example", "TỪ CHỐI"),
    ]
    print(f"CA: {ca_cert.subject.rfc4514_string()}\n")
    print(f"{'Kịch bản':38} | {'Mong đợi':10} | {'verify_chain':44} | TLS (OpenSSL)")
    print("-" * 150)
    failures = 0
    for label, name, hostname, expect in scenarios:
        cert = x509.load_pem_x509_certificate(_load(os.path.join(certs, f"{name}.crt")))
        app_ok, app_reason = pki_verify.verify_chain(cert, ca_cert, crl, hostname)

        httpd = make_server(0, os.path.join(certs, f"{name}.crt"), os.path.join(certs, f"{name}.key"), www, host="127.0.0.1")
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            status, _ = tls_client.fetch("127.0.0.1", port, ca_crt, crl_pem, hostname)
            tls_result = f"THÀNH CÔNG (HTTP {status})"
        except ssl.SSLCertVerificationError as exc:
            tls_result = f"TỪ CHỐI: {exc.verify_message}"
        finally:
            httpd.shutdown(); httpd.server_close()

        got_app = "THÀNH CÔNG" if app_ok else "TỪ CHỐI"
        got_tls = "THÀNH CÔNG" if tls_result.startswith("THÀNH CÔNG") else "TỪ CHỐI"
        verdict = "OK" if (got_app == expect and got_tls == expect) else "SAI"
        failures += verdict == "SAI"
        print(f"{label:38} | {expect:10} | {app_reason[:44]:44} | {tls_result}  [{verdict}]")
    print(f"\nKết quả: {len(scenarios) - failures}/{len(scenarios)} kịch bản đúng mong đợi. Thư mục làm việc: {root}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
