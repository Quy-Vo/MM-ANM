# 🛡️ BÀI TẬP LỚN 1: ỨNG DỤNG MẬT MÃ VÀ TRUYỀN THÔNG BẢO MẬT

**Dự án bao gồm 2 phần chính:**
1. **Phần 1.1:** Xây dựng hệ thống Chat và truyền tệp mã hóa đầu cuối (E2E) chống tấn công Man-in-the-Middle (MitM).
2. **Phần 1.2:** Triển khai hạ tầng Khóa công khai nội bộ (Internal CA) cấp phát chứng thư X.509 cho HTTPS.

---

## ⚙️ YÊU CẦU HỆ THỐNG VÀ CÀI ĐẶT

- **Python:** Phiên bản `3.10` trở lên.

### 1. Tạo và kích hoạt môi trường ảo (Virtual Environment)
Khuyến nghị sử dụng môi trường ảo để cài đặt các thư viện một cách độc lập. Mở Terminal/CMD tại thư mục gốc của dự án và chạy:

**Trên Windows (PowerShell/CMD):**
```powershell
# Tạo môi trường ảo tên là .venv
python -m venv .venv

# Kích hoạt môi trường ảo
.\.venv\Scripts\activate
```
> 💡 **Lưu ý:** Nếu dùng PowerShell và gặp lỗi *Execution Policy*, hãy chạy lệnh sau:
> `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

**Trên macOS/Linux:**
```bash
# Tạo môi trường ảo tên là .venv
python3 -m venv .venv

# Kích hoạt môi trường ảo
source .venv/bin/activate
```

### 2. Cài đặt thư viện
Sau khi đã kích hoạt môi trường ảo (thấy chữ `(.venv)` ở đầu dòng lệnh), tiến hành cài đặt thư viện:

```bash
pip install cryptography pytest
```

> ⚠️ **QUAN TRỌNG:** Tất cả các lệnh chạy Demo dưới đây đều phải được thực thi trong thư mục chứa mã nguồn (ví dụ: `srcs/` hoặc `src/`) và **bắt buộc** phải trong môi trường ảo đã kích hoạt.

---

## 💬 PHẦN 1.1: CHAT VÀ TRUYỀN TỆP MÃ HÓA ĐẦU CUỐI (E2E)

### 1. Công nghệ và Lồng ghép MSSV
- **Trao đổi khóa:** `X25519` (Diffie-Hellman đường cong Elliptic).
- **Chữ ký số:** `Ed25519` (Xác thực danh tính, chống MitM).
- **Mã hóa đối xứng:** `AES-256-GCM`.
- **Dẫn xuất khóa:** `HKDF-SHA256`.

**📌 Lồng ghép MSSV (`2412915`, `2413675`, `2412965`):**
- Chuỗi Handshake gửi đi bắt buộc chứa: `Hello, We are 2412915, 2413675, 2412965`.
- Khóa KDF được băm từ: `SHA256("2412915" || "2413675" || "2412965")`.

### 2. Hướng dẫn chạy Demo (Happy Path)

**Bước 1: Tạo khóa định danh** *(Chỉ chạy 1 lần duy nhất)*
```bash
python generate_keys.py Alice Bob
```
*(Lệnh này sinh ra thư mục `keys/` chứa khóa công khai/riêng tư của Alice và Bob).*

**Bước 2: Chạy hệ thống** *(Mở 3 cửa sổ Terminal)*
- **Terminal 1 (Server):** `python server.py`
- **Terminal 2 (Alice):** `python client.py` *(nhập tên: `Alice`)*
- **Terminal 3 (Bob):** `python client.py` *(nhập tên: `Bob`)*

**Bước 3: Giao tiếp** *(Tại cửa sổ Alice, gõ lệnh)*
- **Chat:** `/msg Bob Chào Bob, tin nhắn này được mã hóa E2E!`
- **Gửi File:** `/file Bob ../Sample.txt`

### 3. Kịch bản Demo MitM thụ động (So sánh có mã hóa và không mã hóa)
Kịch bản này chứng minh tầm quan trọng của việc mã hóa dữ liệu. Kẻ tấn công đứng giữa (MitM) sẽ cố gắng đọc trộm thông điệp.

#### 🔴 Trường hợp A: KHÔNG mã hóa (Rủi ro bảo mật)
1. Mở 3 Terminal:
   - **T1 (MitM):** `python mitm_server.py --attack passive --port 50001`
   - **T2 (Alice):** `python client.py --no-crypto --port 50001`
   - **T3 (Bob):** `python client.py --no-crypto --port 50001`
2. **Tại Alice gõ:** `/msg Bob Tài khoản là 123456`
3. **Kết quả:** MitM in ra màn hình dòng chữ: `[MITM] chat Alice->Bob PLAINTEXT = 'Tài khoản là 123456'` *(Đọc được nguyên văn).*

#### 🟢 Trường hợp B: CÓ mã hóa E2E (An toàn)
1. Tắt T2, T3. Giữ nguyên T1 (MitM).
2. Chạy lại 2 Client nhưng bỏ cờ `--no-crypto`:
   - **T2 (Alice):** `python client.py --port 50001`
   - **T3 (Bob):** `python client.py --port 50001`
3. **Tại Alice gõ lại:** `/msg Bob Tài khoản là 123456`
4. **Kết quả:** MitM chỉ in ra được chuỗi vô nghĩa: `[MITM] chat Alice->Bob CIPHERTEXT (28 bytes) bf06...` *(Không thể đọc được nội dung).*

### 4. Kịch bản Demo MitM chủ động (Tấn công sửa đổi gói tin)
Kịch bản này chứng minh chữ ký `Ed25519` phát hiện và chặn đứng kẻ tấn công sửa đổi gói tin bắt tay.

1. Tắt các cửa sổ cũ. Mở 3 cửa sổ Terminal mới:
   - **T1 (MitM):** `python mitm_server.py --attack tamper-hello --port 50001`
   - **T2 (Alice):** `python client.py --port 50001`
   - **T3 (Bob):** `python client.py --port 50001`
2. **Tại Alice gõ:** `/msg Bob Thử tấn công`
3. **Kết quả:** MitM in ra thông báo đã sửa gói tin. Alice và Bob ngay lập tức báo lỗi đỏ `[HANDSHAKE] Từ chối Bob: Chữ ký không hợp lệ...` và chặn đứng gói tin, không cho gửi đi.

---

## 🌐 PHẦN 1.2: HẠ TẦNG KHÓA CÔNG KHAI NỘI BỘ (INTERNAL CA)

### 1. Lồng ghép MSSV vào Chứng thư X.509
Chứng thư số được sinh ra bởi CA nội bộ có chứa thông tin định danh nhóm:
- **Common Name (CN):** `CA-Root-2412915-2413675-2412965`
- **Organizational Unit (OU):** `Faculty of Computer Science and Engineer - 2412915-2413675-2412965`

### 2. Hướng dẫn chạy Demo CA & HTTPS

**Bước 1: Khởi tạo Root CA và cấp phát chứng thư cho Web Server**
```bash
python ca_setup.py
```
*(Kết quả: Sinh ra thư mục `certs/` chứa 4 file: `ca.crt`, `ca.key`, `server.crt`, `server.key`).*

**Bước 2: Khởi chạy Web Server (HTTPS)**
```bash
python https_server.py
```

**Bước 3: Kiểm tra chứng thư trên Trình duyệt**
1. Mở trình duyệt (Chrome/Edge/Cốc Cốc), truy cập: `https://localhost:4443`
2. Trình duyệt sẽ cảnh báo (do CA tự ký). Bấm **Advanced (Nâng cao)** $\rightarrow$ **Proceed to localhost (Tiếp tục)**.
3. Nhấn vào biểu tượng **Ổ khóa** trên thanh địa chỉ $\rightarrow$ Chọn **Connection is secure** $\rightarrow$ **Certificate is valid** *(hoặc xem chi tiết chứng thư)*.
4. Kiểm tra tab **Details (Chi tiết)** tại mục **Issuer (Tổ chức phát hành)** để xác nhận thông tin `CN` và `OU` đã lồng ghép đúng MSSV của nhóm.

