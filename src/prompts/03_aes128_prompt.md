# Prompt cho `src/aes128.py`

- **Nguon goc:** `Buoc 1 (P01-P05)`, `Buoc 4 (P10)`, `Buoc 7 (P16)`, `Buoc 9`.

**Prompt tao code (tu Buoc 1):**
```text
Dựa theo yêu cầu mục 1.1 và mục 2 trong `src/prompts/de_bai.md`, hãy viết file Python thuần `src/aes128.py` cài đặt thuật toán mã hóa đối xứng AES-128 từ nguyên lý gốc cho sinh viên TRAN HUU QUYET (MSSV: 066206014296). Tuyệt đối không dùng thư viện mật mã ngoài; tự cài đặt các phép toán trường hữu hạn, tự tính bảng S-Box từ công thức gốc, mở rộng khóa, mã hóa/giải mã khối và chế độ CBC có padding PKCS#7, kèm hàm sinh khóa bí mật 128-bit lấy từ 128 bit đầu của SHA-256 chuỗi họ tên `"TRAN HUU QUYET"` (dùng hàm từ `src/sha256.py`).
```

**Prompt kiem tra va sua loi (tu Buoc 4, 7):**
```text
Hãy tự kiểm nghiệm tính đúng đắn với test vector chuẩn NIST và rà soát phản biện các lỗ hổng bảo mật, kiểm tra trường hợp biên đầu vào trong `src/aes128.py`.
```
