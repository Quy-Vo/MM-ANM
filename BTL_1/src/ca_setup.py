# ca_setup.py
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

MSSVS = ["2412915", "2413675", "2412965"]
MSSV_STR = "-".join(MSSVS)
os.makedirs("certs", exist_ok=True)

def generate_ca():
    # Tạo Private Key cho CA
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # Yêu cầu đề bài cho Subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"CA-Root-{MSSV_STR}"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"Faculty of Computer Science and Engineer - {MSSV_STR}"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
    ])
    
    # Build Certificate
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(ca_key, hashes.SHA256())

    # Lưu file
    with open("certs/ca.key", "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("certs/ca.crt", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    print("[CA] Đã tạo Root CA thành công.")

def generate_server_cert():
    # Tạo Private Key cho Server
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # Load CA
    with open("certs/ca.key", "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("certs/ca.crt", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Subject cho Server (CN=localhost)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"Faculty of Computer Science and Engineer - {MSSV_STR}"),
    ])

    # Build Server Cert
    server_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        server_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False,
    ).sign(ca_key, hashes.SHA256())

    # Lưu file
    with open("certs/server.key", "wb") as f:
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("certs/server.crt", "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))
    print("[CA] Đã cấp chứng thư cho Server thành công.")

if __name__ == "__main__":
    generate_ca()
    generate_server_cert()