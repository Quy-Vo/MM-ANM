# Bài tập lớn 1.1 — Chat và truyền tệp mã hóa đầu cuối (E2EE)

Đây là bản demo học tập có Client–Server, trao đổi khóa X25519, dẫn xuất khóa HKDF-SHA256, mã hóa/xác thực AES-256-GCM, chữ ký Ed25519 và SHA-256. Server chỉ chuyển tiếp các gói `secure`; nó không giữ khóa phiên và không giải mã nội dung.

> **Lưu ý bảo mật:** Đây là prototype phục vụ bài tập lớn, chưa phải phần mềm sản xuất. Chỉ dùng với dữ liệu thử nghiệm. Khóa công khai phải được xác minh/ghim qua kênh tin cậy; nếu người dùng tự tin cậy khóa do server gửi thì có nguy cơ MitM. Không gửi khóa riêng qua mạng.

## 1. Yêu cầu

- Python 3.10 trở lên
- Thư viện `cryptography`

Cài thư viện:

### Windows
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Nếu PowerShell chặn kích hoạt môi trường, có thể bỏ qua virtual environment và chạy `py -m pip install -r requirements.txt`.

## 2. Tạo danh tính và khóa

Mở terminal tại thư mục gốc dự án:

```powershell
cd srcs
python setup_identity.py Quan 2412915
python setup_identity.py Quy 2412965
python setup_identity.py Trong 2413675
```

MSSV đã được điền theo thông tin nhóm. Danh sách thành viên được cố định theo thứ tự **Quân (2412915), Quý (2412965), Trọng (2413675)**; cả ba client phải dùng cùng thứ tự này khi tính SHA-256 làm salt cho HKDF. Lệnh tạo:
- `keys/Quan_ed25519_private.pem`
- `keys/Quy_ed25519_private.pem`
- `keys/Trong_ed25519_private.pem`
- cập nhật `members.json` với MSSV và khóa công khai.

**Quan trọng:** Trong mô hình chạy trên cùng máy, các khóa riêng cùng nằm trong thư mục dự án chỉ để demo thuận tiện. Khi chạy trên hai máy khác nhau, mỗi người chỉ giữ khóa riêng của mình; trao đổi khóa công khai qua một kênh tin cậy và nhập bản ghi khóa công khai của người kia vào `members.json`. Không sao chép khóa riêng sang máy người khác.

Khóa công khai cần được ghim/kiểm tra qua kênh tin cậy. So sánh fingerprint (có thể dùng chuỗi hex khóa công khai được in khi tạo) qua một kênh độc lập trước khi kết nối.

Nếu `members.json` đã có khóa của thành viên, không chạy lại lệnh tạo khóa cho người đó vì chương trình không ghi đè khóa riêng hiện có.

## 3. Chạy server và hai client

Theo phân công, Quân là Người B, Trọng là Người A và Quý là Người C. Bản demo này có thể chạy hai client Quan và Quy trên cùng máy; danh tính Trọng vẫn được khai báo để danh sách MSSV của cả nhóm được dùng nhất quán trong greeting và HKDF salt.

Mở 3 cửa sổ terminal tại thư mục gốc dự án.

### Terminal 1 — Server
```powershell
cd srcs
python server.py
```

### Terminal 2 — Client Quan
```powershell
cd srcs
python client.py
```
Khi được hỏi tên, nhập `Quan`.

### Terminal 3 — Client Quy
```powershell
cd srcs
python client.py
```
Khi được hỏi tên, nhập `Quy`.

Server mặc định lắng nghe `127.0.0.1:50000`, nghĩa là chỉ máy hiện tại. Để thử trên LAN, đặt biến môi trường `E2E_HOST=0.0.0.0` trước khi chạy server, mở firewall phù hợp và cấu hình `E2E_HOST` trên client thành IP LAN của server. Chỉ làm trong mạng thử nghiệm tin cậy.

## 4. Bắt tay bảo mật và chat

Ở cửa sổ Quan:
```text
/connect Quy
```

Chờ cả hai phía hiện `[HANDSHAKE OK]`. Sau đó kiểm tra:
```text
/sessions
```

Gửi tin nhắn:
```text
/msg Quy Xin chao, day la tin nhan da ma hoa
```

Quy có thể trả lời:
```text
/msg Quan Toi da nhan duoc tin nhan
```

Lệnh `/connect` chỉ cần được khởi tạo từ một phía. Nếu hai phía cùng chạy `/connect` đồng thời, một trong các lần bắt tay có thể bị từ chối do trạng thái đang chờ; hãy thử lại sau khi hoàn tất hoặc khởi động lại client.

## 5. Thử truyền tệp

Tạo `sample.txt` ở thư mục gốc dự án. Từ terminal client Quan:
```text
/file Quy ..\sample.txt
```

Tệp nhận được lưu trong `downloads/`. Kiểm tra SHA-256 trên PowerShell từ thư mục gốc:
```powershell
Get-FileHash .\sample.txt -Algorithm SHA256
Get-FileHash .\downloads\sample.txt -Algorithm SHA256
```
Hai hash phải giống nhau. Nội dung mỗi khối tệp được mã hóa và xác thực bằng AES-GCM trước khi gửi.

## 6. Các phép thử nên trình diễn

1. **Chat bình thường:** bắt tay thành công, gửi/nhận tin nhắn.
2. **Truyền tệp:** gửi tệp văn bản và tệp nhị phân; so sánh SHA-256.
3. **Chưa bắt tay:** mở client, thử `/msg Quy ...` trước `/connect`; chương trình phải từ chối.
4. **Khóa công khai sai:** sao lưu `members.json`, thay một ký tự trong khóa công khai của Quy (vẫn giữ hex hợp lệ), khởi động lại client Quan và thử `/connect Quy`; xác minh chữ ký phải thất bại. Khôi phục file sau thử nghiệm.
5. **Ciphertext bị sửa:** có thể viết test tự động gọi `crypto.aes_gcm_decrypt` với ciphertext bị đổi một byte; phải phát sinh lỗi xác thực `InvalidTag`. Không cần sửa gói đang chạy thực tế.
6. **Server không giải mã:** quan sát server log; server chỉ thấy loại gói, người gửi/người nhận, không có plaintext tin nhắn hoặc khóa phiên.
7. **Tên đang sử dụng:** khởi chạy hai client cùng tên; client thứ hai phải bị từ chối.

### Kiểm tra AES-GCM tamper bằng script
Từ thư mục `srcs`:
```powershell
python -c "import crypto; from cryptography.exceptions import InvalidTag; k=b'K'*32; n,c=crypto.aes_gcm_encrypt(k,b'hello',aad=b'test'); bad=bytearray(c); bad[0]^=1; 
try: crypto.aes_gcm_decrypt(k,n,bytes(bad),aad=b'test'); print('FAIL: tampering accepted')
except InvalidTag: print('PASS: tampering rejected')"
```

## 7. Cách hoạt động ở mức tổng quan

1. Người gửi tạo `HELLO` có MSSV hai bên, session ID, nonce và khóa công khai X25519.
2. Người nhận tạo `HELLO_REPLY`, ký transcript bằng Ed25519.
3. Người khởi tạo kiểm tra chữ ký bằng khóa công khai đã ghim, ký transcript và gửi `AUTH`.
4. Người nhận kiểm tra chữ ký `AUTH`.
5. Hai bên tính bí mật chung X25519 và dùng HKDF-SHA256, salt SHA-256 của chuỗi `241291524129652413675` (nối MSSV theo thứ tự Quân, Quý, Trọng, không có dấu phân cách), cùng transcript/session context để tạo hai khóa AES-256-GCM riêng cho hai chiều. Greeting trong HELLO là `Hello, We are 2412915, 2412965, 2413675`.
6. Gói chat/tệp được mã hóa bằng AES-GCM. Server chỉ chuyển tiếp gói.

## 8. Giới hạn cần ghi trong báo cáo

- Prototype dùng cấu hình khóa công khai tin cậy thủ công, chưa có PKI/CA hoặc giao diện quản lý danh tính.
- Chưa có forward secrecy sau khi khóa Ed25519 dài hạn bị lộ? Khóa DH X25519 là ephemeral cho mỗi handshake, nhưng việc bảo vệ lịch sử phụ thuộc vào không lưu khóa phiên và cách vận hành.
- Chưa có cơ chế tự động kết nối lại, truyền tệp tiếp tục sau gián đoạn, chống spam/rate limiting hoặc giao diện đồ họa.
- Server có thể quan sát metadata (ai gửi cho ai, kích thước/thời điểm gói tin), dù không đọc được plaintext.
- Không tuyên bố “chống mọi MitM”; kết luận phụ thuộc việc khóa Ed25519 của đối tác đã được xác minh qua kênh độc lập.

## 9. Cấu trúc dự án

```text
BTL1_1_E2E_Chat/
├── README.md
├── requirements.txt
├── members.json
├── keys/                  # khóa riêng; không nộp/chia sẻ ra ngoài nhóm
├── downloads/
├── refs/
└── srcs/
    ├── client.py
    ├── server.py
    ├── protocol.py
    ├── config.py
    ├── file_transfer.py
    ├── crypto.py
    ├── handshake.py
    └── setup_identity.py
```
