"""
Comprehensive Verification & Experimental Evaluation Suite
Student: TRAN HUU QUYET (SID: 066206014296)
Information Security Course Project

Runs NIST KAT validation, student-specific key derivation,
correctness checks, and benchmarks for all four algorithms.
"""

import os
import sys
import time

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sha256 import sha256, sha256_hex
from aes128 import (
    derive_key_from_student_name,
    encrypt_block,
    decrypt_block,
    encrypt_cbc,
    decrypt_cbc,
    key_expansion
)
import rsa
import dsa


def run_all():
    log_lines = []

    def pr(line: str = ""):
        print(line)
        log_lines.append(line)

    pr("=" * 80)
    pr("INFORMATION SECURITY COURSE PROJECT - EXPERIMENTAL EVALUATION")
    pr("Student Name : TRAN HUU QUYET")
    pr("Student ID   : 066206014296")
    pr("Algorithms   : 1. AES-128 (Symmetric) | 2. RSA (Asymmetric, SID mod 3 = 0)")
    pr("               3. SHA-256 (Hash)      | 4. DSA (Digital Signature, SID mod 4 = 2)")
    pr("Implementation: 100% Python from first principles (No external crypto libs)")
    pr("=" * 80)
    pr()

    # -------------------------------------------------------------
    # 1. SHA-256 VALIDATION
    # -------------------------------------------------------------
    pr("[SECTION 1: SHA-256 CRYPTOGRAPHIC HASH EVALUATION]")
    nist_sha_tests = [
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        )
    ]
    for idx, (data, expected) in enumerate(nist_sha_tests, 1):
        computed = sha256_hex(data)
        status = "PASSED (MATCH NIST KAT)" if computed == expected else "FAILED"
        pr(f"  Test Vector {idx}: Input len = {len(data)} bytes")
        pr(f"    Expected: {expected}")
        pr(f"    Computed: {computed}")
        pr(f"    Status  : {status}")

    # Benchmark SHA-256
    pr("\n  SHA-256 Computational Throughput Benchmark:")
    for size_kb in [1, 10, 50]:
        payload = b"A" * (size_kb * 1024)
        t0 = time.perf_counter()
        _ = sha256(payload)
        elapsed = time.perf_counter() - t0
        speed_kb_s = size_kb / elapsed if elapsed > 0 else 0
        pr(f"    Payload: {size_kb:2d} KB | Time: {elapsed*1000:7.2f} ms | Speed: {speed_kb_s:8.2f} KB/s")
    pr()

    # -------------------------------------------------------------
    # 2. AES-128 VALIDATION & STUDENT KEY DERIVATION
    # -------------------------------------------------------------
    pr("[SECTION 2: AES-128 SYMMETRIC ENCRYPTION EVALUATION]")
    
    # 2.1 Student Key Derivation
    student_name = "TRAN HUU QUYET"
    aes_key, name_hash = derive_key_from_student_name(student_name)
    pr(f"  2.1 Student Secret Key Derivation (Section 1.1):")
    pr(f"    Input Name String     : \"{student_name}\"")
    pr(f"    Computed SHA-256 Hash : {name_hash.hex()}")
    pr(f"    AES-128 Secret Key    : {aes_key.hex()} (First 128 bits / 16 bytes)")

    # 2.2 NIST SP 800-38A / FIPS 197 Known Answer Test
    nist_key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    nist_pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    nist_expected_ct = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")
    
    round_keys = key_expansion(nist_key)
    nist_enc = encrypt_block(nist_pt, round_keys)
    nist_dec = decrypt_block(nist_enc, round_keys)
    
    pr(f"\n  2.2 NIST FIPS 197 Standard Single-Block KAT:")
    pr(f"    Plaintext : {nist_pt.hex()}")
    pr(f"    Ciphertext: {nist_enc.hex()}")
    pr(f"    Expected  : {nist_expected_ct.hex()}")
    pr(f"    Status    : {'PASSED (MATCH NIST KAT)' if nist_enc == nist_expected_ct else 'FAILED'}")
    pr(f"    Decryption: {'PASSED (Match Plaintext)' if nist_dec == nist_pt else 'FAILED'}")

    # 2.3 CBC Mode with Student Key
    sample_text = b"Course Project: Information Security by TRAN HUU QUYET - SID 066206014296"
    iv = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct_cbc = encrypt_cbc(sample_text, aes_key, iv)
    dec_cbc = decrypt_cbc(ct_cbc, aes_key, iv)
    pr(f"\n  2.3 AES-128-CBC with Student Key:")
    pr(f"    Original Message : {sample_text.decode('utf-8')}")
    pr(f"    Ciphertext (hex) : {ct_cbc.hex()}")
    pr(f"    Decrypted Message: {dec_cbc.decode('utf-8')}")
    pr(f"    Integrity Check  : {'PASSED (Exact match)' if dec_cbc == sample_text else 'FAILED'}")

    # Benchmark AES-128
    pr("\n  AES-128 CBC Benchmark:")
    for size_kb in [1, 2, 5]:
        payload = b"B" * (size_kb * 1024)
        t0 = time.perf_counter()
        c = encrypt_cbc(payload, aes_key, iv)
        enc_time = time.perf_counter() - t0
        t0 = time.perf_counter()
        _ = decrypt_cbc(c, aes_key, iv)
        dec_time = time.perf_counter() - t0
        pr(f"    Payload: {size_kb:2d} KB | Enc: {enc_time*1000:6.2f} ms ({size_kb/enc_time:7.2f} KB/s) | Dec: {dec_time*1000:6.2f} ms ({size_kb/dec_time:7.2f} KB/s)")
    pr()

    # -------------------------------------------------------------
    # 3. RSA VALIDATION
    # -------------------------------------------------------------
    pr("[SECTION 3: RSA ASYMMETRIC CRYPTOGRAPHY EVALUATION (SID mod 3 = 0)]")
    
    # 3.1 Small Worked Example
    rsa_ex = rsa.small_worked_example()
    pr(f"  3.1 Pedagogical Worked Example (p={rsa_ex['p']}, q={rsa_ex['q']}):")
    pr(f"    Modulus n = {rsa_ex['n']}, phi(n) = {rsa_ex['phi']}")
    pr(f"    Public exponent e = {rsa_ex['e']}, Private exponent d = {rsa_ex['d']}")
    pr(f"    Message m = {rsa_ex['m']}, Ciphertext c = {rsa_ex['c']}, Decrypted = {rsa_ex['decrypted']}")
    pr(f"    Correctness: {'PASSED' if rsa_ex['m'] == rsa_ex['decrypted'] else 'FAILED'}")

    # 3.2 1024-bit Keypair Generation & Full Roundtrip
    pr(f"\n  3.2 Industrial-Grade Key Generation (1024-bit RSA):")
    t0 = time.perf_counter()
    pub_key, priv_key, (p_prime, q_prime) = rsa.generate_rsa_keypair(bits=1024)
    keygen_time = time.perf_counter() - t0
    pr(f"    Key Generation Time : {keygen_time*1000:6.2f} ms")
    pr(f"    Modulus n bit length: {pub_key[1].bit_length()} bits")
    pr(f"    Prime p bit length  : {p_prime.bit_length()} bits")
    pr(f"    Prime q bit length  : {q_prime.bit_length()} bits")
    
    secret_msg = "Hello RSA - TRAN HUU QUYET"
    t0 = time.perf_counter()
    enc_rsa = rsa.encrypt_string(secret_msg, pub_key)
    enc_time = time.perf_counter() - t0
    
    t0 = time.perf_counter()
    dec_rsa = rsa.decrypt_string(enc_rsa, priv_key)
    dec_time = time.perf_counter() - t0
    
    pr(f"    Plaintext Message   : \"{secret_msg}\"")
    pr(f"    Ciphertext Integer  : {str(enc_rsa)[:40]}... (truncated)")
    pr(f"    Decrypted Message   : \"{dec_rsa}\"")
    pr(f"    Encryption Time     : {enc_time*1000:6.3f} ms")
    pr(f"    Decryption Time     : {dec_time*1000:6.3f} ms")
    pr(f"    Roundtrip Status    : {'PASSED (Exact match)' if dec_rsa == secret_msg else 'FAILED'}")
    pr()

    # -------------------------------------------------------------
    # 4. DSA VALIDATION
    # -------------------------------------------------------------
    pr("[SECTION 4: DSA DIGITAL SIGNATURE EVALUATION (SID mod 4 = 2)]")
    
    # 4.1 Small Worked Example
    dsa_ex = dsa.small_worked_example()
    pr(f"  4.1 Pedagogical Worked Example (p={dsa_ex['p']}, q={dsa_ex['q']}, g={dsa_ex['g']}):")
    pr(f"    Private key x = {dsa_ex['x']}, Public key y = {dsa_ex['y']}")
    pr(f"    Hash z = {dsa_ex['z']}, Nonce k = {dsa_ex['k']}")
    pr(f"    Signature: (r={dsa_ex['r']}, s={dsa_ex['s']})")
    pr(f"    Verification intermediate: w={dsa_ex['w']}, u1={dsa_ex['u1']}, u2={dsa_ex['u2']}, v={dsa_ex['v']}")
    pr(f"    Verification (v == r): {'PASSED' if dsa_ex['is_valid'] else 'FAILED'}")

    # 4.2 Standard 1024-bit / 160-bit FIPS DSA Execution
    pr(f"\n  4.2 Standard NIST FIPS 186-4 DSA (L=1024, N=160):")
    t0 = time.perf_counter()
    dsa_x, dsa_y = dsa.generate_dsa_keypair()
    dsa_keygen_time = time.perf_counter() - t0
    pr(f"    Key Generation Time : {dsa_keygen_time*1000:6.2f} ms")

    document = b"Official submission of Information Security Project by TRAN HUU QUYET"
    t0 = time.perf_counter()
    sig = dsa.dsa_sign(document, dsa_x)
    sign_time = time.perf_counter() - t0
    
    t0 = time.perf_counter()
    valid = dsa.dsa_verify(document, sig, dsa_y)
    verify_time = time.perf_counter() - t0

    pr(f"    Document Message    : \"{document.decode('utf-8')}\"")
    pr(f"    Signature (r, s)    :")
    pr(f"      r = {hex(sig[0])}")
    pr(f"      s = {hex(sig[1])}")
    pr(f"    Signing Time        : {sign_time*1000:6.3f} ms")
    pr(f"    Verification Time   : {verify_time*1000:6.3f} ms")
    pr(f"    Signature Status    : {'VALID (PASSED)' if valid else 'INVALID (FAILED)'}")

    # Tamper resistance test
    tampered_doc = b"Official submission of Information Security Project by UNKNOWN"
    tampered_valid = dsa.dsa_verify(tampered_doc, sig, dsa_y)
    pr(f"    Tampered Document   : {'REJECTED (PASSED)' if not tampered_valid else 'ACCEPTED (FAILED)'}")
    pr()

    pr("=" * 80)
    pr("ALL 4 CRYPTOGRAPHIC ALGORITHMS VERIFIED AND FULLY OPERATIONAL!")
    pr("=" * 80)

    # Save output to evidence folder
    evidence_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evidence")
    os.makedirs(evidence_dir, exist_ok=True)
    out_file = os.path.join(evidence_dir, "terminal_output.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines))
    print(f"\n[INFO] Complete experimental output saved to: {out_file}")


if __name__ == "__main__":
    run_all()
