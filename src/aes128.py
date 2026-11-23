"""
AES-128 (Advanced Encryption Standard) from first principles.
Author: TRAN HUU QUYET (SID: 066206014296)
Following NIST FIPS 197 standard.
"""

from typing import List, Tuple
from sha256 import sha256


# --- Galois Field GF(2^8) Arithmetic ---

def xtime(b: int) -> int:
    """Multiplication by 2 in GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)."""
    return ((b << 1) ^ 0x1B) & 0xFF if (b & 0x80) else (b << 1) & 0xFF


def gf_multiply(a: int, b: int) -> int:
    """Multiplication of two elements in GF(2^8)."""
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        a = xtime(a)
        b >>= 1
    return res


def gf_inverse(a: int) -> int:
    """Multiplicative inverse in GF(2^8) using Fermat's Little Theorem (a^254 mod m(x))."""
    if a == 0:
        return 0
    res = 1
    base = a
    for _ in range(7):
        base = gf_multiply(base, base)
        res = gf_multiply(res, base)
    return res


def _build_sbox() -> Tuple[List[int], List[int]]:
    """Derive AES S-Box and Inverse S-Box algebraically from first principles."""
    sbox = [0] * 256
    inv_sbox = [0] * 256
    c = 0x63
    for byte_val in range(256):
        inv = gf_inverse(byte_val)
        # Affine transformation over GF(2)
        s = 0
        for i in range(8):
            bit = (
                ((inv >> i) & 1)
                ^ ((inv >> ((i + 4) % 8)) & 1)
                ^ ((inv >> ((i + 5) % 8)) & 1)
                ^ ((inv >> ((i + 6) % 8)) & 1)
                ^ ((inv >> ((i + 7) % 8)) & 1)
                ^ ((c >> i) & 1)
            )
            s |= bit << i
        sbox[byte_val] = s
        inv_sbox[s] = byte_val
    return sbox, inv_sbox


S_BOX, INV_S_BOX = _build_sbox()


# --- Round Constants (Rcon) ---

def _build_rcon() -> List[int]:
    rcon = [0] * 11
    val = 1
    for i in range(1, 11):
        rcon[i] = val
        val = xtime(val)
    return rcon


RCON = _build_rcon()


# --- Key Expansion ---

def _rot_word(word: int) -> int:
    """Cyclic byte rotation [a0, a1, a2, a3] -> [a1, a2, a3, a0]."""
    return ((word << 8) & 0xFFFFFFFF) | (word >> 24)


def _sub_word(word: int) -> int:
    """Apply S-box to each byte of a 4-byte word."""
    b0 = S_BOX[(word >> 24) & 0xFF]
    b1 = S_BOX[(word >> 16) & 0xFF]
    b2 = S_BOX[(word >> 8) & 0xFF]
    b3 = S_BOX[word & 0xFF]
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3


def key_expansion(key: bytes) -> List[List[List[int]]]:
    """
    Expand a 16-byte (128-bit) key into 11 round keys of shape 4x4.
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")

    words = [0] * 44
    for i in range(4):
        words[i] = int.from_bytes(key[i * 4 : (i + 1) * 4], "big")

    for i in range(4, 44):
        temp = words[i - 1]
        if i % 4 == 0:
            temp = _sub_word(_rot_word(temp)) ^ (RCON[i // 4] << 24)
        words[i] = words[i - 4] ^ temp

    round_keys = []
    for r in range(11):
        round_state = [[0] * 4 for _ in range(4)]
        for col in range(4):
            w = words[r * 4 + col]
            round_state[0][col] = (w >> 24) & 0xFF
            round_state[1][col] = (w >> 16) & 0xFF
            round_state[2][col] = (w >> 8) & 0xFF
            round_state[3][col] = w & 0xFF
        round_keys.append(round_state)
    return round_keys


# --- State Matrix Transformations ---

def bytes_to_state(block: bytes) -> List[List[int]]:
    """Convert 16 bytes into a 4x4 column-major state matrix."""
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def state_to_bytes(state: List[List[int]]) -> bytes:
    """Convert a 4x4 state matrix back to 16 bytes."""
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = state[r][c]
    return bytes(out)


def add_round_key(state: List[List[int]], round_key: List[List[int]]) -> List[List[int]]:
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]


def sub_bytes(state: List[List[int]]) -> List[List[int]]:
    return [[S_BOX[state[r][c]] for c in range(4)] for r in range(4)]


def inv_sub_bytes(state: List[List[int]]) -> List[List[int]]:
    return [[INV_S_BOX[state[r][c]] for c in range(4)] for r in range(4)]


def shift_rows(state: List[List[int]]) -> List[List[int]]:
    res = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            res[r][c] = state[r][(c + r) % 4]
    return res


def inv_shift_rows(state: List[List[int]]) -> List[List[int]]:
    res = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            res[r][c] = state[r][(c - r) % 4]
    return res


def mix_columns(state: List[List[int]]) -> List[List[int]]:
    res = [[0] * 4 for _ in range(4)]
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        res[0][c] = gf_multiply(0x02, s0) ^ gf_multiply(0x03, s1) ^ s2 ^ s3
        res[1][c] = s0 ^ gf_multiply(0x02, s1) ^ gf_multiply(0x03, s2) ^ s3
        res[2][c] = s0 ^ s1 ^ gf_multiply(0x02, s2) ^ gf_multiply(0x03, s3)
        res[3][c] = gf_multiply(0x03, s0) ^ s1 ^ s2 ^ gf_multiply(0x02, s3)
    return res


def inv_mix_columns(state: List[List[int]]) -> List[List[int]]:
    res = [[0] * 4 for _ in range(4)]
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        res[0][c] = gf_multiply(0x0E, s0) ^ gf_multiply(0x0B, s1) ^ gf_multiply(0x0D, s2) ^ gf_multiply(0x09, s3)
        res[1][c] = gf_multiply(0x09, s0) ^ gf_multiply(0x0E, s1) ^ gf_multiply(0x0B, s2) ^ gf_multiply(0x0D, s3)
        res[2][c] = gf_multiply(0x0D, s0) ^ gf_multiply(0x09, s1) ^ gf_multiply(0x0E, s2) ^ gf_multiply(0x0B, s3)
        res[3][c] = gf_multiply(0x0B, s0) ^ gf_multiply(0x0D, s1) ^ gf_multiply(0x09, s2) ^ gf_multiply(0x0E, s3)
    return res


# --- Block Cipher Core ---

def encrypt_block(block: bytes, round_keys: List[List[List[int]]]) -> bytes:
    state = bytes_to_state(block)
    state = add_round_key(state, round_keys[0])

    for round_idx in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_idx])

    # Final round without MixColumns
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    return state_to_bytes(state)


def decrypt_block(block: bytes, round_keys: List[List[List[int]]]) -> bytes:
    state = bytes_to_state(block)
    state = add_round_key(state, round_keys[10])

    for round_idx in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round_idx])
        state = inv_mix_columns(state)

    # Final round without InvMixColumns
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return state_to_bytes(state)


# --- PKCS#7 Padding & Modes ---

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % 16 != 0:
        raise ValueError("Invalid padded block length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid PKCS#7 padding byte")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("PKCS#7 padding corrupted")
    return data[:-pad_len]


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """CBC Mode Encryption with PKCS#7 padding."""
    if len(iv) != 16:
        raise ValueError("IV must be exactly 16 bytes for AES-128")
    round_keys = key_expansion(key)
    padded = pkcs7_pad(plaintext)
    ciphertext = bytearray()
    prev_block = iv

    for i in range(0, len(padded), 16):
        block = padded[i : i + 16]
        xored = bytes(b ^ p for b, p in zip(block, prev_block))
        enc = encrypt_block(xored, round_keys)
        ciphertext.extend(enc)
        prev_block = enc
    return bytes(ciphertext)


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """CBC Mode Decryption with PKCS#7 unpadding."""
    if len(iv) != 16:
        raise ValueError("IV must be exactly 16 bytes for AES-128")
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16")
    round_keys = key_expansion(key)
    plaintext = bytearray()
    prev_block = iv

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i : i + 16]
        dec = decrypt_block(block, round_keys)
        xored = bytes(d ^ p for d, p in zip(dec, prev_block))
        plaintext.extend(xored)
        prev_block = block
    return pkcs7_unpad(bytes(plaintext))


# --- Key Generation for Student Project ---

def derive_key_from_student_name(full_name: str = "TRAN HUU QUYET") -> Tuple[bytes, bytes]:
    """
    Implements Section 1.1:
    1. Input string: student full name
    2. Compute SHA-256 hash value
    3. Take first 128 bits (16 bytes) as AES-128 secret key
    Returns: (key_128_bytes, full_sha256_hash_bytes)
    """
    name_bytes = full_name.encode("utf-8")
    full_hash = sha256(name_bytes)
    aes_key = full_hash[:16]
    return aes_key, full_hash
