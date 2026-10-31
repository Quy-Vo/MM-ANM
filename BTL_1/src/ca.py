"""
ca.py — Dịch vụ Cấp phát & Quản lý Chứng thư số (Certificate Authority) nội bộ, chuẩn X.509.

Lệnh (python ca.py <lệnh> ...):
  init                    tạo Root CA (CN/OU chứa MSSV) và CRL rỗng đầu tiên
  issue --cn NAME ...     cấp chứng thư cho Web Server (tạo khóa mới, hoặc ký CSR bằng --csr)
  revoke --serial HEX     thu hồi chứng thư và phát hành lại CRL
  gen-crl                 phát hành lại CRL (danh sách thu hồi)
  list                    liệt kê chứng thư đã cấp và trạng thái

Thư mục:
  pki/    trạng thái của CA: ca.key (BÍ MẬT), ca.crt, index.json (sổ cấp phát), crl.pem
  certs/  chứng thư/khóa đã cấp cho máy chủ
  www/    bản công khai của ca.crt và ca.crl để máy chủ web phân phối
"""
from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import os
import shutil
import sys
from datetime import timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from config import MSSVS

MSSV_STR = "-".join(MSSVS)
CA_CN = f"CA-Root-{MSSV_STR}"
# Đề bài dùng dấu gạch dài (–) giữa "Engineer" và danh sách MSSV.
OU_TEXT = f"Faculty of Computer Science and Engineer \u2013 {MSSV_STR}"

CA_DIR = os.environ.get("PKI_DIR", "pki")
CERT_DIR = os.environ.get("CERT_DIR", "certs")
WWW_DIR = os.environ.get("WWW_DIR", "www")
CRL_URL = os.environ.get("CRL_URL", "http://localhost:8080/ca.crl")

REASONS = {
    "unspecified": x509.ReasonFlags.unspecified,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
}


class CAError(Exception):
    pass


def _now() -> datetime.datetime:
    return datetime.datetime.now(timezone.utc)


def _paths(ca_dir: str) -> dict:
    return {
        "key": os.path.join(ca_dir, "ca.key"),
        "crt": os.path.join(ca_dir, "ca.crt"),
        "index": os.path.join(ca_dir, "index.json"),
        "crl": os.path.join(ca_dir, "crl.pem"),
    }


def _write_private(path: str, key) -> None:
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _load_ca(ca_dir: str):
    p = _paths(ca_dir)
    if not (os.path.isfile(p["key"]) and os.path.isfile(p["crt"])):
        raise CAError(f"Chưa khởi tạo CA trong '{ca_dir}'. Chạy: python ca.py init")
    with open(p["key"], "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    with open(p["crt"], "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return key, cert


def _load_index(ca_dir: str) -> dict:
    with open(_paths(ca_dir)["index"], encoding="utf-8") as f:
        return json.load(f)


def _save_index(ca_dir: str, index: dict) -> None:
    path = _paths(ca_dir)["index"]
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def _subject(cn: str, with_country: bool = False) -> x509.Name:
    attrs = [
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, OU_TEXT),
    ]
    if with_country:
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"))
    return x509.Name(attrs)


def _publish(ca_dir: str, www_dir: str | None) -> None:
    """Chép bản công khai (ca.crt, ca.crl) sang thư mục web."""
    if not www_dir:
        return
    os.makedirs(www_dir, exist_ok=True)
    p = _paths(ca_dir)
    shutil.copyfile(p["crt"], os.path.join(www_dir, "ca.crt"))
    shutil.copyfile(p["crl"], os.path.join(www_dir, "ca.crl"))


# --------------------------------------------------------------------------- #
def init_ca(ca_dir: str = CA_DIR, *, days: int = 3650, key_size: int = 2048,
            force: bool = False, www_dir: str | None = None, cn: str = CA_CN) -> x509.Certificate:
    p = _paths(ca_dir)
    if os.path.exists(p["key"]) and not force:
        raise CAError(f"CA đã tồn tại trong '{ca_dir}' (dùng --force để tạo lại).")
    os.makedirs(ca_dir, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = _subject(cn, with_country=True)
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    _write_private(p["key"], key)
    with open(p["crt"], "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    _save_index(ca_dir, {"crl_number": 0, "issued": {}})
    gen_crl(ca_dir, www_dir=www_dir)
    return cert


def _parse_sans(sans: list[str]) -> list[x509.GeneralName]:
    names = []
    for s in sans:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(s)))
        except ValueError:
            names.append(x509.DNSName(s))
    return names


def issue(ca_dir: str = CA_DIR, *, cn: str | None = None, sans: list[str] | None = None,
          days: int = 365, out_dir: str = CERT_DIR, name: str = "server", csr_path: str | None = None,
          backdate_days: int = 0, key_size: int = 2048) -> tuple[x509.Certificate, int]:
    """Cấp chứng thư Web Server. Không có --csr thì tạo khóa mới và lưu <out_dir>/<name>.key."""
    ca_key, ca_cert = _load_ca(ca_dir)
    os.makedirs(out_dir, exist_ok=True)

    if csr_path:
        with open(csr_path, "rb") as f:
            csr = x509.load_pem_x509_csr(f.read())
        if not csr.is_signature_valid:
            raise CAError("CSR có chữ ký không hợp lệ (không chứng minh được sở hữu khóa riêng).")
        public_key = csr.public_key()
        if cn is None:
            attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            cn = attrs[0].value if attrs else None
        if not sans:
            try:
                ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                sans = [str(v) for v in ext.get_values_for_type(x509.DNSName)] + \
                       [str(v) for v in ext.get_values_for_type(x509.IPAddress)]
            except x509.ExtensionNotFound:
                sans = []
        key = None
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = key.public_key()

    if not cn:
        raise CAError("Thiếu Common Name (--cn).")
    sans = sans or [cn]
    now = _now()
    not_before = now - timedelta(days=backdate_days) - timedelta(minutes=1)
    not_after = now - timedelta(days=backdate_days) + timedelta(days=days)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_subject(cn)).issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before).not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName(_parse_sans(sans)), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=True, content_commitment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier(CRL_URL)], relative_name=None,
            reasons=None, crl_issuer=None)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert_path = os.path.join(out_dir, f"{name}.crt")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    if key is not None:
        _write_private(os.path.join(out_dir, f"{name}.key"), key)

    index = _load_index(ca_dir)
    index["issued"][format(cert.serial_number, "x")] = {
        "cn": cn, "sans": sans, "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
        "status": "valid", "revoked_at": None, "reason": None,
    }
    _save_index(ca_dir, index)
    return cert, cert.serial_number


def gen_crl(ca_dir: str = CA_DIR, *, next_update_days: float = 7, backdate_days: float = 0,
            www_dir: str | None = None) -> x509.CertificateRevocationList:
    ca_key, ca_cert = _load_ca(ca_dir)
    index = _load_index(ca_dir)
    index["crl_number"] = int(index.get("crl_number", 0)) + 1
    now = _now() - timedelta(days=backdate_days)   # backdate_days chỉ dùng để mô phỏng CRL cũ khi kiểm thử
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now - timedelta(minutes=1))
        .next_update(now + timedelta(days=next_update_days))
        .add_extension(x509.CRLNumber(index["crl_number"]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    )
    for serial_hex, rec in index["issued"].items():
        if rec["status"] != "revoked":
            continue
        entry = (x509.RevokedCertificateBuilder()
                 .serial_number(int(serial_hex, 16))
                 .revocation_date(datetime.datetime.fromisoformat(rec["revoked_at"])))
        reason = REASONS.get(rec.get("reason") or "unspecified", x509.ReasonFlags.unspecified)
        if reason != x509.ReasonFlags.unspecified:
            entry = entry.add_extension(x509.CRLReason(reason), critical=False)
        builder = builder.add_revoked_certificate(entry.build())
    crl = builder.sign(ca_key, hashes.SHA256())
    with open(_paths(ca_dir)["crl"], "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    _save_index(ca_dir, index)
    _publish(ca_dir, www_dir)
    return crl


def revoke(ca_dir: str = CA_DIR, *, serial: str, reason: str = "unspecified",
           www_dir: str | None = None) -> None:
    if reason not in REASONS:
        raise CAError(f"Lý do không hợp lệ. Chọn: {', '.join(REASONS)}")
    serial_hex = serial.lower().replace("0x", "").replace(":", "")
    index = _load_index(ca_dir)
    rec = index["issued"].get(serial_hex)
    if rec is None:
        raise CAError(f"Không có chứng thư serial {serial_hex} trong sổ cấp phát.")
    if rec["status"] != "revoked":
        rec.update(status="revoked", revoked_at=_now().isoformat(), reason=reason)
        _save_index(ca_dir, index)
    gen_crl(ca_dir, www_dir=www_dir)


def list_issued(ca_dir: str = CA_DIR) -> list[tuple[str, dict]]:
    return sorted(_load_index(ca_dir)["issued"].items(), key=lambda kv: kv[1]["not_before"])


# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CA nội bộ (X.509 + CRL)")
    ap.add_argument("--ca-dir", default=CA_DIR)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init"); s.add_argument("--force", action="store_true"); s.add_argument("--www", default=WWW_DIR)
    s = sub.add_parser("issue")
    s.add_argument("--cn", default=None); s.add_argument("--san", action="append", default=None)
    s.add_argument("--days", type=int, default=365); s.add_argument("--name", default="server")
    s.add_argument("--out", default=CERT_DIR); s.add_argument("--csr", default=None)
    s = sub.add_parser("revoke")
    s.add_argument("--serial", required=True); s.add_argument("--reason", default="unspecified", choices=list(REASONS))
    s.add_argument("--www", default=WWW_DIR)
    s = sub.add_parser("gen-crl"); s.add_argument("--www", default=WWW_DIR)
    sub.add_parser("list")
    a = ap.parse_args(argv)

    try:
        if a.cmd == "init":
            cert = init_ca(a.ca_dir, force=a.force, www_dir=a.www)
            print(f"[CA] Đã tạo Root CA: {cert.subject.rfc4514_string()}")
        elif a.cmd == "issue":
            cert, serial = issue(a.ca_dir, cn=a.cn, sans=a.san, days=a.days, out_dir=a.out, name=a.name, csr_path=a.csr)
            print(f"[CA] Đã cấp chứng thư serial={serial:x} → {a.out}/{a.name}.crt")
        elif a.cmd == "revoke":
            revoke(a.ca_dir, serial=a.serial, reason=a.reason, www_dir=a.www)
            print(f"[CA] Đã thu hồi serial={a.serial} và phát hành lại CRL.")
        elif a.cmd == "gen-crl":
            crl = gen_crl(a.ca_dir, www_dir=a.www)
            print(f"[CA] Đã phát hành CRL ({len(list(crl))} mục thu hồi).")
        elif a.cmd == "list":
            for serial, rec in list_issued(a.ca_dir):
                print(f"{serial}  {rec['status']:8}  CN={rec['cn']}  hết hạn={rec['not_after'][:10]}")
    except CAError as exc:
        print(f"[CA] Lỗi: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
