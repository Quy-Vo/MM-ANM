# Bài Tập Lớn 1: Phát Triển Ứng Dụng Mật Mã & Truyền Thông Bảo Mật

Dự án này là hệ thống truyền thông bảo mật đầu cuối (Client-Server) kết hợp cùng hạ tầng khóa công khai (PKI). Mục tiêu nhằm trao đổi tin nhắn, tệp tin an toàn và phòng chống tấn công Man-in-the-Middle (MitM).

## 👥 Nhóm Thực Hiện
* **Thành viên 1:** Võ Nguyễn Phú Quý - MSSV: 2412965
* **Thành viên 2:** [Tên thành viên 2] - MSSV: [MSSV_2]
* **Thành viên 3:** [Tên thành viên 3] - MSSV: [MSSV_3]

## 🏗 Cấu Trúc Thư Mục
Dự án được chia thành 2 module chính:

1. **`P1_SecureChat/`**: Hệ thống Chat và truyền file bảo mật.
   * Sử dụng Diffie-Hellman & RSA để trao đổi khóa phiên (Bắt tay 4 bước).
   * Khóa khởi tạo (KDF): `Key = SHA256(MSSV_1 || MSSV_2)`
   * Mã hóa dữ liệu: AES-256-CBC kết hợp HMAC-SHA256 chống giả mạo.
2. **`P2_PKI_CA/`**: Dịch vụ Cấp phát Chứng thư số (CA) nội bộ.
   * Tiêu chuẩn X.509 với Subject chứa MSSV nhóm.
   * Tích hợp cơ chế kiểm tra thu hồi chứng thư (CRL / OCSP).

## 🚀 Hướng Dẫn Cài Đặt (Prerequisites)
Yêu cầu hệ thống phải cài đặt sẵn:
* **Python 3.8+** (Dành cho phần Secure Chat)
* **OpenSSL & Nginx** (Dành cho phần CA & Web Server trên Linux/WSL)

**Cài đặt thư viện Python:**
```bash
cd P1_SecureChat
pip install -r requirements.txt
```

## 🛠 Hướng Dẫn Chạy Demo

### 1. Khởi chạy hệ thống Chat (P1)
Mở 2 Terminal khác nhau để mô phỏng Server và Client:

**Terminal 1 (Lắng nghe kết nối):**
```bash
python P1_SecureChat/server.py
```

**Terminal 2 (Thực hiện kết nối):**
```bash
python P1_SecureChat/client.py --host 127.0.0.1 --port 9999
```

### 2. Triển khai Hệ thống CA (P2)
Di chuyển vào thư mục P2 và chạy script tự động:
```bash
cd P2_PKI_CA
chmod +x setup_ca.sh
./setup_ca.sh
```
*Lệnh này sẽ tự động sinh Root CA, cấp phát chứng thư cho Web Server và khởi chạy dịch vụ OCSP ở cổng 8888.*

## 🛡 Phân Tích An Toàn (Tấn Công MitM)
Chi tiết về các kịch bản thử nghiệm đánh chặn (Eavesdropping, Tampering, Active MitM) được trình bày cụ thể trong thư mục `Docs/` và file báo cáo `.docx`.