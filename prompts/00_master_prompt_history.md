# Lich su 9 buoc prompt tao va chinh sua project

---

## Buoc 1 (P01-P05) | 2026-11-23 12:10 - 12:38
**File tao ra:** `src/*.py`, `report/main.tex`, `report/references.bib`, `report/chapters/ch1_aes.tex` - `ch5_evaluation.tex`, `README.md`

```text
Đọc toàn bộ yêu cầu đề bài trong file `src/prompts/de_bai.md` và thông tin cá nhân của tôi (Họ tên: TRAN HUU QUYET, MSSV: 066206014296), hãy kiểm tra kỹ lại toàn bộ yêu cầu rồi triển khai hoàn chỉnh đồ án bằng tiếng Anh:
1. Xác định 4 thuật toán theo đúng quy tắc đề bài: AES-128 (khóa 128-bit lấy từ 128 bit đầu của SHA-256 chuỗi họ tên `"TRAN HUU QUYET"`), RSA (chữ số cuối MSSV `6 mod 3 = 0`), SHA-256 (bắt buộc) và DSA (chữ số cuối MSSV `6 mod 4 = 2`).
2. Viết mã nguồn Python thuần từ nguyên lý gốc trong thư mục `src/`, tuyệt đối không dùng thư viện mật mã có sẵn (như cryptography, PyCryptodome, PyNaCl, hashlib, OpenSSL), kèm file chạy thực nghiệm kiểm tra tính đúng đắn, đo hiệu năng và lưu kết quả ra `evidence/terminal_output.txt`.
3. Viết báo cáo bằng LaTeX (chạy được trên Overleaf) trong thư mục `report/` đảm bảo đủ 8 mục bắt buộc cho mỗi thuật toán (gồm cả ví dụ minh họa tính tay từng bước, code Python và đánh giá thực nghiệm), kèm file hướng dẫn chạy.
```

---

## Buoc 2 (P06-P07) | 2026-11-23 13:11 - 13:14
**File chinh sua:** `report/main.tex`, `README.md`

```text
Sửa lại trang bìa của báo cáo theo mẫu báo cáo cũ đính kèm: Giảng viên hướng dẫn là Dr. Tran The Vinh, mã lớp học phần An toàn thông tin là 012012303303, kiểm tra lại năm học cho đúng thời điểm hiện tại, bổ sung logo UTH và đảm bảo toàn bộ nội dung đều là tiếng Anh.
```

---

## Buoc 3 (P08-P09) | 2026-11-23 13:18 - 13:27
**File chinh sua:** `report/main.tex`, `report/chapters/ch1_aes.tex` - `ch4_dsa.tex`

```text
Kiểm tra lại toàn bộ báo cáo từ những chi tiết nhỏ nhất như kích thước và cách trình bày dựa trên 3 ảnh chụp trang PDF đính kèm. Đánh giá khách quan xem bản hiện tại đã đạt chuẩn chuyên nghiệp để nộp chưa và sửa các điểm trình bày chưa ổn.
```

---

## Buoc 4 (P10) | 2026-11-23 13:36
**File chinh sua:** `report/chapters/ch1_aes.tex`

```text
Kiểm nghiệm và xác thực lại tính đúng đắn của các thuật toán, code Python cũng như minh chứng thực nghiệm, sau đó đối chiếu với nội dung trong báo cáo xem đã khớp hoàn toàn chưa.
```

---

## Buoc 5 (P11) | 2026-11-23 13:42
**File chinh sua:** `report/references.bib`, `report/chapters/ch1_aes.tex`, `ch2_rsa.tex`, `ch4_dsa.tex`, `ch5_evaluation.tex`

```text
Kiểm nghiệm lại toàn bộ nguồn tài liệu tham khảo trong `references.bib` và các trích dẫn trong báo cáo xem đã trung thực và chuẩn xác chưa.
```

---

## Buoc 6 (P12-P14) | 2026-11-23 13:46 - 14:33
**File chinh sua:** `report/main.tex`, `report/chapters/ch1_aes.tex` - `ch4_dsa.tex`

```text
Từ các ảnh chụp trang PDF đính kèm cho thấy khi sửa khối này thì các khối khác bị chèn đè lên nhau. Hãy kiểm tra kỹ toàn bộ bố cục hiển thị của báo cáo để tìm và sửa dứt điểm các lỗi chèn khối, tràn lề.
```

---

## Buoc 7 (P16) | 2026-11-23 14:42
**File chinh sua:** `src/math_utils.py`, `src/aes128.py`, `src/dsa.py`, `report/chapters/ch1_aes.tex`, `ch4_dsa.tex`, `ch5_evaluation.tex`, `README.md`

```text
Hãy kiểm tra phản biện toàn diện một cách độc lập để tìm ra các lỗi toán học, lỗ hổng bảo mật, trường hợp biên trong mã nguồn Python cũng như các sai sót không nhất quán giữa code và báo cáo LaTeX rồi khắc phục triệt để (thực hiện qua quy trình `/doubt-driven-development` trong IDE).
```

---

## Buoc 8 (P17) | 2026-11-23 15:03
**File chinh sua:** `src/__init__.py`, `src/math_utils.py`, `src/rsa.py`, `src/dsa.py`, `src/run_experiments.py`, `report/chapters/ch4_dsa.tex`

```text
Hãy rà soát chuyên sâu chất lượng toàn bộ dự án theo nhiều khía cạnh (tính đúng đắn, khả năng đọc hiểu, cấu trúc tổ chức, bảo mật và độ khớp của minh chứng với báo cáo), đồng thời chỉnh sửa các điểm chưa đạt chuẩn và chạy kiểm thử lại toàn bộ hệ thống (thực hiện qua quy trình `/code-review-and-quality /boost` trong IDE).
```

---

## Buoc 9 | 2026-11-27 11:49 - 12:36
**File chinh sua:** `src/math_utils.py`, `src/sha256.py`, `src/aes128.py`, `src/rsa.py`, `src/dsa.py`, `evidence/terminal_output.txt`, `report/main.tex`, `report/chapters/ch1_aes.tex` - `ch5_evaluation.tex`, `report/chapters/appendix_prompts.tex`

```text
Kiểm nghiệm và xác thực lại tính đúng đắn của các thuật toán, code Python cũng như minh chứng thực nghiệm, sau đó đối chiếu với nội dung trong báo cáo xem đã khớp hoàn toàn chưa.
Kiểm tra phản biện toàn diện một cách độc lập để tìm ra các lỗi toán học, lỗ hổng bảo mật, trường hợp biên trong mã nguồn Python cũng như các sai sót không nhất quán giữa code và báo cáo LaTeX rồi khắc phục triệt để.
Kiểm tra lại toàn bộ báo cáo từ những chi tiết nhỏ nhất như kích thước và cách trình bày. Đánh giá khách quan xem bản hiện tại đã đạt chuẩn chuyên nghiệp để nộp chưa và sửa các điểm trình bày chưa ổn.
```
