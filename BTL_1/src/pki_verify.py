"""
pki_verify.py — Xác thực chứng thư máy chủ: chuỗi tin cậy, thời hạn, tên máy chủ, mục đích dùng và THU HỒI (CRL).

verify_chain(cert, ca_cert, crl, hostname) -> (ok: bool, reason: str)
Mọi lỗi đều "đóng" (fail closed): thiếu CRL, CRL hết hạn hoặc ký sai đều bị từ chối.
"""
from __future__ import annotations

import datetime
import ipaddress
from datetime import timezone

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


def _utc(obj, name: str) -> datetime.datetime:
    value = getattr(obj, name + "_utc", None)
    if value is None:
        value = getattr(obj, name)
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
    return value


def _hostname_ok(cert: x509.Certificate, hostname: str) -> bool:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    try:
        ip = ipaddress.ip_address(hostname)
        return ip in san.get_values_for_type(x509.IPAddress)
    except ValueError:
        pass
    host = hostname.lower()
    for dns in san.get_values_for_type(x509.DNSName):
        dns = dns.lower()
        if dns == host:
            return True
        if dns.startswith("*.") and host.count(".") == dns.count(".") and host.endswith(dns[1:]):
            return True
    return False


def verify_chain(cert: x509.Certificate, ca_cert: x509.Certificate, crl: x509.CertificateRevocationList | None,
                 hostname: str, *, now: datetime.datetime | None = None, require_crl: bool = True):
    now = now or datetime.datetime.now(timezone.utc)

    # 1. CA phải là CA và đang còn hạn
    try:
        bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return False, "Chứng thư CA không có BasicConstraints"
    if not bc.ca:
        return False, "Chứng thư gốc không phải CA"
    if not (_utc(ca_cert, "not_valid_before") <= now <= _utc(ca_cert, "not_valid_after")):
        return False, "Chứng thư CA hết hạn hoặc chưa hiệu lực"

    # 2. Chữ ký của CA trên chứng thư máy chủ
    try:
        cert.verify_directly_issued_by(ca_cert)
    except Exception:
        return False, "Không do CA tin cậy cấp (chữ ký/issuer không khớp)"

    # 3. Thời hạn
    if now < _utc(cert, "not_valid_before"):
        return False, "Chứng thư chưa có hiệu lực"
    if now > _utc(cert, "not_valid_after"):
        return False, "Chứng thư đã hết hạn"

    # 4. Tên máy chủ
    if not _hostname_ok(cert, hostname):
        return False, f"Tên máy chủ '{hostname}' không khớp SAN của chứng thư"

    # 5. Mục đích sử dụng
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            return False, "Chứng thư không dành cho xác thực máy chủ TLS"
    except x509.ExtensionNotFound:
        pass

    # 6. Thu hồi (CRL)
    if crl is None:
        if require_crl:
            return False, "Không có CRL để kiểm tra thu hồi"
        return True, "Hợp lệ (không kiểm tra thu hồi)"
    if crl.issuer != ca_cert.subject:
        return False, "CRL không do CA này phát hành"
    if not crl.is_signature_valid(ca_cert.public_key()):
        return False, "Chữ ký CRL không hợp lệ"
    if now > _utc(crl, "next_update"):
        return False, "CRL đã hết hạn (cần phát hành lại)"
    entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    if entry is not None:
        try:
            reason = entry.extensions.get_extension_for_class(x509.CRLReason).value.reason.name
        except x509.ExtensionNotFound:
            reason = "unspecified"
        return False, f"Chứng thư đã bị thu hồi (lý do: {reason})"
    return True, "Hợp lệ: đúng CA, còn hạn, đúng tên máy chủ, chưa bị thu hồi"
