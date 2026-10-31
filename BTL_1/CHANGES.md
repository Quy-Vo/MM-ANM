# Thay đổi so với bản trước (vai trò C — rà soát và sửa lỗi)

| # | Vấn đề | Sửa |
|---|---|---|
| 1 | Chat bị phát lại vẫn được nhận | `secure_session.py`: counter trong AAD, bên nhận chỉ nhận counter tăng |
| 2 | `file_meta` (tên/kích thước/SHA-256) đi plaintext, đổi tên tệp không bị phát hiện | `file_meta` và `file_end` được mã hóa + xác thực; kiểm tra `total` khớp `size` |
| 3 | Thiếu khóa pin làm `SystemExit` trong luồng nhận, client ngừng nhận | `PeerKeyError` (ValueError); mỗi gói lỗi được bắt riêng, luồng nhận không chết |
| 4 | Gõ sai tên người nhận thoát cả chương trình | Lỗi được in ra, chương trình tiếp tục |
| 5 | Handshake lỗi/timeout không thử lại được | `_fail()` xóa trạng thái; lần gửi sau bắt tay lại từ đầu |
| 6 | Bên kia khởi động lại thì kẹt phiên cũ | Bên nhận báo `no_session`, bên gửi bỏ phiên cũ; hello mới thay phiên cũ sau khi confirm hợp lệ |
| 7 | Tên đối phương ghép thẳng vào đường dẫn | `valid_name()` ở client và server; server đặt lại trường `from` |
| + | Responder kích hoạt phiên trước khi xác nhận khóa của initiator | Chỉ kích hoạt sau `hs_confirm` hợp lệ |
| + | Hai bên khởi tạo cùng lúc đều thất bại | Bên tên nhỏ hơn giữ vai khởi tạo, bên kia nhường |
| + | `swap-eph` sai offset sau khi thêm `hello_str` | Phân tích bằng `Hello.from_bytes` |
| + | Proxy chưa có MitM thật, sửa ciphertext, replay | Thêm `impersonate`, `tamper-ct`, `replay` |
| + | `tests/` không chạy từ thư mục gốc | `tests/conftest.py` |
| + | Chứng thư thiếu extension, `utcnow()` cũ | `BasicConstraints`, `KeyUsage`, `EKU serverAuth`, SKI/AKI, `datetime.now(timezone.utc)` |

Khác biệt giao thức: trường `nonce` của gói đổi thành `hdr` (dạng `"<counter>:<nonce_hex>"`).

## Phần 1.2 (CA)

- `ca.py`: CA có sổ cấp phát (`pki/index.json`): `init`, `issue` (khóa mới hoặc từ CSR), `revoke`, `gen-crl`, `list`.
- CRL có chữ ký, CRL Number, lý do thu hồi; chứng thư có CRL Distribution Points.
- `pki_verify.py`: xác thực chuỗi, thời hạn, tên máy chủ, EKU và thu hồi; mọi lỗi đều từ chối.
- `tls_client.py`: kiểm tra CRL ngay ở tầng TLS (`VERIFY_CRL_CHECK_LEAF`).
- `pki_demo.py`: 5 kịch bản xác thực chạy tự động (hợp lệ, thu hồi, CA lạ, hết hạn, sai tên).
- `https_server.py`: chỉ phục vụ `www/`, tắt liệt kê thư mục (bản cũ phục vụ thư mục làm việc nên có thể tải được khóa riêng).
- OU dùng dấu gạch dài `–` đúng như đề.
- Client in `Hello, We are ... | SHA256(MSSV)=...` khi thiết lập phiên để làm bằng chứng cho yêu cầu MSSV.
