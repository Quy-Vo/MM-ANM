"""
ca_setup.py — Cài đặt nhanh: tạo Root CA (CN/OU chứa MSSV), cấp chứng thư cho localhost, sinh CRL.

Tương đương: python ca.py init && python ca.py issue --cn localhost --san localhost --san 127.0.0.1
Kết quả: pki/ (trạng thái CA), certs/ (ca.crt, server.crt, server.key), www/ (ca.crt, ca.crl công khai).
"""
import os
import shutil

import ca

if __name__ == "__main__":
    try:
        cert = ca.init_ca(www_dir=ca.WWW_DIR)
    except ca.CAError as exc:
        print(f"[CA] {exc}  -> dùng CA hiện có")
    else:
        print(f"[CA] Đã tạo Root CA: {cert.subject.rfc4514_string()}")
    _, serial = ca.issue(cn="localhost", sans=["localhost", "127.0.0.1"])
    os.makedirs(ca.CERT_DIR, exist_ok=True)
    shutil.copyfile(os.path.join(ca.CA_DIR, "ca.crt"), os.path.join(ca.CERT_DIR, "ca.crt"))
    print(f"[CA] Đã cấp chứng thư cho Server (serial={serial:x}) → {ca.CERT_DIR}/server.crt")
