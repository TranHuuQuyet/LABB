# CẨM NANG BẢO VỆ VÀ VẤN ĐÁP CODE (ORAL DEFENSE CHEAT SHEET)
**Trường:** Đại học Giao thông Vận tải TP. HCM (UTH) - Viện CNTT & Điện, Điện tử
**Môn học:** An toàn thông tin (Mã lớp học phần: `012012303303`)
**Giảng viên hướng dẫn:** TS. Trần Thế Vinh
**Sinh viên thực hiện:** Trần Hữu Quyết | **MSSV:** 066206014296

Tài liệu này được biên soạn nhằm giúp bạn tự tin 100% khi giảng viên kiểm tra, phỏng vấn từng dòng code hoặc hỏi về lý thuyết toán học của 4 thuật toán.

---

## 1. THUẬT TOÁN AES-128 (`src/aes128.py`)

### Khóa học của bạn được tạo như thế nào?
- **Đầu vào:** Chuỗi ký tự họ và tên đầy đủ: `"TRAN HUU QUYET"`.
- **Băm:** Chạy qua hàm `sha256("TRAN HUU QUYET".encode("utf-8"))`.
  - Giá trị hash 256-bit: `b90d458f695d64c3aaedc61180c96c66d43bbd5c677e7d9c669820f729e771c0`.
- **Lấy khóa AES:** Lấy đúng **16 bytes đầu tiên** (128 bits):
  - `b90d458f695d64c3aaedc61180c96c66`.

### Các câu hỏi giảng viên hay hỏi về AES:
1. **"Tại sao code không dùng mảng tĩnh S-Box copy từ mạng về?"**
   - *Trả lời:* Em tự xây dựng bảng S-Box từ nguyên lý gốc đại số (Galois Field $GF(2^8)$). Mỗi byte $a$ trước hết được tìm phần tử nghịch đảo nhân $a^{-1} = a^{254} \pmod{m(x)}$ trong trường Galois (với $m(x) = x^8 + x^4 + x^3 + x + 1$ hay `0x11B`), sau đó đưa qua phép biến đổi Affine trên $\mathbb{Z}_2$. Điều này chứng minh code hiểu bản chất tại sao S-Box triệt tiêu tính tuyến tính để chống vi sai (differential cryptanalysis).
2. **"Hàm `xtime(b)` dùng để làm gì?"**
   - *Trả lời:* `xtime` là phép nhân một byte với đa thức $x$ (tức nhân 2) trong trường Galois. Ta dịch trái 1 bit (`b << 1`). Nếu bit cao nhất ban đầu bằng 1 (tràn bậc 8), ta XOR với `0x1B` (tương ứng với $x^4 + x^3 + x + 1$) để rút gọn.
3. **"Quy trình 1 Round của AES gồm những gì?"**
   - *Trả lời:* Gồm 4 bước:
     - `SubBytes`: Thay thế phi tuyến từng byte qua S-Box.
     - `ShiftRows`: Dịch vòng các hàng (hàng 0 dịch 0, hàng 1 dịch 1, hàng 2 dịch 2, hàng 3 dịch 3).
     - `MixColumns`: Phép nhân ma trận cột với ma trận cố định trong $GF(2^8)$ để khuếch tán dữ liệu (Round cuối thứ 10 bỏ qua bước này).
     - `AddRoundKey`: XOR trạng thái State với khóa con Round Key sinh ra từ Key Expansion.

---

## 2. THUẬT TOÁN RSA (`src/rsa.py`)

### Nhận diện đề bài:
- MSSV tận cùng là `6` $\implies 6 \pmod 3 = 0 \implies$ Thuật toán **RSA**.

### Các câu hỏi giảng viên hay hỏi về RSA:
1. **"Làm sao sinh được 2 số nguyên tố lớn $p, q$ trong Python thuần mà không dùng thư viện ngoài?"**
   - *Trả lời:* Em dùng hàm `generate_prime(bits)` trong `math_utils.py`. Hàm này chọn một số lẻ ngẫu nhiên bằng CSPRNG `secrets` rồi kiểm tra tính nguyên tố bằng thuật toán xác suất **Miller-Rabin** qua 40 vòng lặp. Xác suất một hợp số vượt qua được bài test là cực kỳ nhỏ ($4^{-40} \approx 8.27 \times 10^{-25}$).
2. **"Tại sao số mũ công khai $e$ thường chọn là 65537?"**
   - *Trả lời:* $65537 = 2^{16} + 1$ là số nguyên tố Fermat $F_4$. Ở dạng nhị phân, nó là `10000000000000001` (chỉ có 2 bit 1). Khi thực hiện phép lũy thừa modulo nhanh (Square-and-Multiply), ta chỉ cần 16 phép bình phương và duy nhất 1 phép nhân, giúp tốc độ mã hóa và kiểm tra chữ ký cực nhanh.
3. **"Tìm khóa bí mật $d$ bằng cách nào?"**
   - *Trả lời:* $d$ là nghịch đảo modulo của $e$ theo modulo $\phi(n) = (p-1)(q-1)$, tức $e \cdot d \equiv 1 \pmod{\phi(n)}$. Em cài đặt giải thuật **Euclid mở rộng (Extended Euclidean Algorithm)** trong hàm `mod_inverse` để tìm các hệ số Bézout, từ đó suy ra $d$.

---

## 3. THUẬT TOÁN SHA-256 (`src/sha256.py`)

### Các câu hỏi giảng viên hay hỏi về SHA-256:
1. **"Cơ chế đệm dữ liệu (Padding) của SHA-256 diễn ra thế nào?"**
   - *Trả lời:* Với chuỗi $L$ bit:
     - Thêm bit `1` đầu tiên (byte `0x80`).
     - Thêm các byte `0x00` sao cho độ dài mới đồng dư $448 \pmod{512}$ (tức chừa đúng 64 bit cuối).
     - 64 bit cuối cùng chứa giá trị độ dài gốc $L$ dưới dạng big-endian.
     - Kết quả tạo thành khối có độ dài là bội số của 512 bit (64 bytes).
2. **"Các hằng số khởi tạo $H$ và $K$ trong code được lấy từ đâu?"**
   - *Trả lời:* Toàn bộ được tạo tự động trong code từ nguyên tắc "nothing-up-my-sleeve":
     - 8 giá trị $H_0 \dots H_7$: Lấy 32 bit đầu phần thập phân căn bậc 2 của 8 số nguyên tố đầu tiên (2 đến 19).
     - 64 giá trị $K_0 \dots K_{63}$: Lấy 32 bit đầu phần thập phân căn bậc 3 của 64 số nguyên tố đầu tiên (2 đến 311).
3. **"Message Schedule $W_t$ được mở rộng như thế nào?"**
   - *Trả lời:* 16 từ đầu ($W_0 \dots W_{15}$) lấy từ 64 bytes của khối tin nhắn. Từ $W_{16}$ đến $W_{63}$ được mở rộng theo công thức:
     $$W_t = \sigma_1(W_{t-2}) + W_{t-7} + \sigma_0(W_{t-15}) + W_{t-16} \pmod{2^{32}}$$
     trong đó $\sigma_0, \sigma_1$ sử dụng các phép xoay phải bit (`ROTR`) và dịch phải bit (`SHR`).

---

## 4. THUẬT TOÁN DSA (`src/dsa.py`)

### Nhận diện đề bài:
- MSSV tận cùng là `6` $\implies 6 \pmod 4 = 2 \implies$ Thuật toán **DSA (Digital Signature Algorithm)**.

### Các câu hỏi giảng viên hay hỏi về DSA:
1. **"Cấu trúc nhóm của DSA khác gì so với RSA?"**
   - *Trả lời:* RSA làm việc trên vành $\mathbb{Z}_n$ với $n = pq$. DSA làm việc trên một **nhóm con Cyclic cấp nguyên tố $q$** nằm trong trường hữu hạn $\mathbb{Z}_p^*$, trong đó $q \mid (p-1)$. Phần tử sinh $g$ thỏa mãn $g^q \equiv 1 \pmod p$. Nhờ làm việc trong nhóm con cấp $q$, kích thước chữ ký DSA $(r, s)$ chỉ dài cỡ $2 \times 160$ bit (hoặc $2 \times 256$ bit), nhỏ hơn rất nhiều so với RSA.
2. **"Phương trình ký và xác minh của DSA là gì?"**
   - *Ký:* Chọn số ngẫu nhiên $k \in [1, q-1]$:
     $$r = (g^k \bmod p) \bmod q$$
     $$s = k^{-1} (H(m) + x \cdot r) \bmod q$$
   - *Xác minh:* Tính $w = s^{-1} \bmod q$, $u_1 = (H(m) \cdot w) \bmod q$, $u_2 = (r \cdot w) \bmod q$.
     $$v = ((g^{u_1} \cdot y^{u_2}) \bmod p) \bmod q$$
     Chữ ký hợp lệ khi và chỉ khi $v == r$.
3. **"Hiểm họa lớn nhất của DSA là gì nếu lập trình sai?"**
   - *Trả lời:* Đó là việc **tái sử dụng hoặc để lộ số ngẫu nhiên $k$ (ephemeral nonce)**. Nếu dùng chung $k$ cho 2 tin nhắn khác nhau, kẻ tấn công chỉ cần lấy hiệu $s_1 - s_2$ là tính được $k$, từ đó giải ra ngay khóa bí mật $x$ của hệ thống. (Đây chính là lỗ hổng kinh điển khiến hãng Sony bị hacker bẻ khóa máy PlayStation 3 năm 2010).

---

## 5. CÁCH TRÌNH DIỄN CODE KHI THẦY CÔ YÊU CẦU CHẠY THỬ
Khi giảng viên yêu cầu chạy thử nghiệm thực tế:
1. Mở Terminal trên máy Mac của bạn.
2. Điều hướng đến thư mục dự án:
   ```bash
   cd /Users/quyettranhuu/Documents/LABB
   ```
3. Chạy lệnh:
   ```bash
   python3 src/run_experiments.py
   ```
4. Chỉ cho thầy cô thấy các điểm cốt lõi trên màn hình:
   - Dòng sinh khóa từ tên `"TRAN HUU QUYET"` và chuỗi Hex 16 bytes đầu tiên.
   - Các dòng chữ `PASSED (MATCH NIST KAT)` màu xanh khẳng định thuật toán tự viết khớp 100% với chuẩn quốc tế.
   - Dòng test tính năng chống giả mạo của DSA: khi tin nhắn bị sửa đổi, hệ thống in ra `REJECTED (PASSED)`.
