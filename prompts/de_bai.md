# De bai goc Information Security Course Project
---

## 1. Project Requirements

Each student is required to complete an individual course project involving the study and implementation of modern cryptographic techniques. The project shall consist of the following four components.

### 1.1. Symmetric-key Cryptography
Study and implement:
- **AES-128 (Advanced Encryption Standard).**
- Key length: **128 bits**.
- The secret key shall be generated according to the following procedure:
  - Use the student's **full name** as the input string.
  - Compute its **SHA-256** hash value.
  - Use the **first 128 bits** of the hash output as the secret key for AES-128.

### 1.2. Asymmetric-key Cryptography
Each student shall study and implement **one** of the following algorithms. The assigned algorithm is determined by the **last digit of the Student ID (SID)** according to the following rule:
- `0`: RSA
- `1`: Diffie-Hellman (DH)
- `2`: Elliptic Curve Cryptography (ECC)

### 1.3. Cryptographic Hash Function
Study and implement:
- **SHA-256 (Secure Hash Algorithm 256-bit).**

### 1.4. Digital Signature
Each student shall study and implement **one** of the following digital signature algorithms. The assigned algorithm is determined by the **last digit of the Student ID (SID)** according to the following rule:
- `0`: ElGamal Digital Signature
- `1`: Schnorr Digital Signature
- `2`: Digital Signature Algorithm (DSA)
- `3`: Elliptic Curve Digital Signature Algorithm (ECDSA)

---

## 2. Project Objectives

For each assigned algorithm, the report shall include the following:
1. Present the historical background, development, and design motivation of the algorithm.
2. Explain the underlying mathematical foundations and operating principles.
3. Describe the complete operational procedure (encryption/decryption, key exchange, hashing, digital signing, or signature verification, as applicable).
4. Analyze the security assumptions, security properties, and known attacks against the algorithm.
5. Discuss the advantages, limitations, and practical applications of the algorithm in modern information systems.
6. Provide a complete worked example illustrating the algorithm step by step.
7. Implement the algorithm in **Python** from first principles. The use of existing cryptographic libraries or frameworks (e.g., `cryptography`, `PyCryptodome`, `PyNaCl`, or OpenSSL APIs) is **strictly prohibited**. Only Python's standard libraries may be used for general computation and data processing.
8. Evaluate the implementation through experimental results, analyze its correctness and computational performance, and provide concluding remarks.

---

## 3. Academic Integrity

- Students are required to conduct their own research, complete all work independently, and assume full responsibility for the entire content of both the course report and the implementation.
- Any form of plagiarism, including copying another student's work or allowing others to copy one's own work, is strictly prohibited.
- Artificial Intelligence (AI) tools may be used **only as supplementary reference tools**. Students are **not permitted to copy and paste AI-generated content verbatim** into the course report or source code without their own analysis, verification, and substantial revision.
- All materials referenced from books, journal articles, websites, or any other sources must be properly cited in accordance with the principles of academic integrity.
- The instructor reserves the right to inspect, compare, interview, or require students to explain any part of the submitted report and source code. **Any violation of the academic integrity policy will result in a score of zero for the course project.**

---

## 4. Submission Requirements

Students are required to submit their course project in **both** of the following formats:

### Hard Copy
- Submit one printed and bound copy of the course report **on the final examination date**.

### Electronic Submission (Soft Copy)
Upload the following materials to the designated submission system as instructed by the instructor:
- The course report (PDF or DOCX format).
- The complete source code of the implementation.
- Supporting evidence demonstrating the implementation and experimental results, including screenshots, videos, or documentation describing the execution process and the corresponding outputs.
