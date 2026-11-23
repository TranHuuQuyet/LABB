# Information Security Course Project
**Study and Implementation of Modern Cryptographic Techniques from First Principles**

- **Institution:** Ho Chi Minh City University of Transport (UTH)
- **Faculty / Institute:** Institute of Information Technology and Electrical & Electronics Engineering
- **Course / Class ID:** Information Security (Course Class ID: `012012303303`)
- **Instructor:** Dr. Tran The Vinh
- **Student Name:** Tran Huu Quyet
- **Student ID:** 066206014296
- **Date:** Ho Chi Minh City, November 2026
- **Assigned Topic Set:**
  1. **Symmetric-Key Cryptography:** AES-128 (Key derived from SHA-256 of `"TRAN HUU QUYET"`)
  2. **Asymmetric-Key Cryptography:** RSA ($066206014296 \pmod 3 = 0$)
  3. **Cryptographic Hash Function:** SHA-256 (Mandatory for all students)
  4. **Digital Signature:** DSA ($\text{Last digit } 6 \pmod 4 = 2$)

---

## 1. Project Structure

```text
LABB/
├── src/                          # Pure Python implementations (First Principles)
│   ├── math_utils.py             # Number-theoretic routines (Miller-Rabin, EGCD, pow_mod)
│   ├── sha256.py                 # Pure Python SHA-256 (FIPS 180-4)
│   ├── aes128.py                 # Pure Python AES-128 (FIPS 197, ECB/CBC, PKCS#7)
│   ├── rsa.py                    # Pure Python RSA (KeyGen, Encrypt, Decrypt)
│   ├── dsa.py                    # Pure Python DSA (FIPS 186-4, Sign, Verify)
│   └── run_experiments.py        # Automated test suite, NIST KAT vectors & benchmarks
├── report/                       # Complete LaTeX report (Overleaf-ready)
│   ├── main.tex                  # Master document with Title page, TOC, Integrity statement
│   ├── references.bib            # Academic citations (NIST FIPS, RFCs, Papers)
│   └── chapters/
│       ├── ch1_aes.tex           # AES-128 (8 mandatory sections)
│       ├── ch2_rsa.tex           # RSA (8 mandatory sections)
│       ├── ch3_sha256.tex        # SHA-256 (8 mandatory sections)
│       ├── ch4_dsa.tex           # DSA (8 mandatory sections)
│       └── ch5_evaluation.tex    # Comparative analysis & conclusion
├── evidence/                     # Experimental execution proof for submission
│   └── terminal_output.txt       # Raw captured execution log of all test passes
├── ORAL_DEFENSE_GUIDE.md         # Comprehensive Q&A and code explanation guide for interviews
└── README.md                     # This file
```

---

## 2. Compliance with "First Principles" Policy

As mandated by the course requirements:
- **Zero Third-Party Cryptographic Libraries:** No modules such as `cryptography`, `PyCryptodome`, `PyNaCl`, or OpenSSL are imported.
- **Native Implementation:** 
  - All Galois Field $\text{GF}(2^8)$ multiplications and the non-linear S-box are generated mathematically from polynomial inversion $a^{254} \pmod{m(x)}$ and affine bit-shifts.
  - SHA-256 constants are computed from the fractional parts of prime square/cube roots.
  - Modular inverses are calculated via the Extended Euclidean Algorithm.
  - Large prime generation is powered by a custom Miller-Rabin primality test.

---

## 3. How to Run the Software Implementation

### Prerequisites
- Python 3.8+ (using only standard built-in libraries `math`, `random`, `sys`, `time`).

### Run All Verifications and Benchmarks
To execute the automated evaluation suite (validates NIST Known Answer Tests, student-specific key derivation, and performance benchmarks):

```bash
python3 src/run_experiments.py
```

### Inspect Output Evidence
The execution automatically writes the full terminal output to:
```bash
cat evidence/terminal_output.txt
```

---

## 4. How to Compile the LaTeX Report

### Option A: Overleaf (Recommended - Zero Installation)
1. Zip the `report/` folder:
   ```bash
   cd report && zip -r ../report.zip ./* && cd ..
   ```
2. Go to [Overleaf](https://www.overleaf.com), click **New Project** $\rightarrow$ **Upload Project**, and select `report.zip`.
3. Click **Recompile** to view and download the official PDF.

### Option B: Local Compilation on macOS (Optional)
If you have MacTeX / BasicTeX installed:
```bash
cd report
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```
