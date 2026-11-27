"""
SHA-256 implementation from first principles.
Author: TRAN HUU QUYET (SID: 066206014296)
Following NIST FIPS 180-4 standard.
"""

import math
from typing import List, Tuple

# Mask for 32-bit unsigned integer operations
MASK_32 = 0xFFFFFFFF


def _generate_primes(count: int) -> List[int]:
    """Sieve to find the first 'count' prime numbers."""
    primes = []
    candidate = 2
    while len(primes) < count:
        is_p = True
        limit = int(math.isqrt(candidate))
        for p in primes:
            if p > limit:
                break
            if candidate % p == 0:
                is_p = False
                break
        if is_p:
            primes.append(candidate)
        candidate += 1
    return primes


# Mathematical derivation of initial hash values (H0) and round constants (K)
# according to FIPS 180-4: fractional parts of square and cube roots of primes.
_PRIMES_64 = _generate_primes(64)
INITIAL_HASH_H: Tuple[int, ...] = tuple(
    int((p**0.5 - int(p**0.5)) * (2**32)) for p in _PRIMES_64[:8]
)
ROUND_CONSTANTS_K: Tuple[int, ...] = tuple(
    int((p**(1/3) - int(p**(1/3))) * (2**32)) for p in _PRIMES_64
)


def rotr(val: int, shift: int) -> int:
    """Rotate right 32-bit integer."""
    return ((val >> shift) | (val << (32 - shift))) & MASK_32


def shr(val: int, shift: int) -> int:
    """Shift right 32-bit integer."""
    return (val >> shift) & MASK_32


def ch(x: int, y: int, z: int) -> int:
    """Conditional choice function: (x AND y) XOR (NOT x AND z)."""
    return ((x & y) ^ ((~x & MASK_32) & z)) & MASK_32


def maj(x: int, y: int, z: int) -> int:
    """Majority vote function: (x AND y) XOR (x AND z) XOR (y AND z)."""
    return (x & y) ^ (x & z) ^ (y & z)


def big_sigma0(x: int) -> int:
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def big_sigma1(x: int) -> int:
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def small_sigma0(x: int) -> int:
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)


def small_sigma1(x: int) -> int:
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)


def pad_message(data: bytes) -> bytes:
    """
    Pad message to a multiple of 512 bits (64 bytes).
    Appends 1 bit (0x80), k zero bytes, and 64-bit big-endian length.
    """
    orig_bit_len = len(data) * 8
    # Append 0x80 byte
    padded = bytearray(data)
    padded.append(0x80)

    # Pad with 0x00 until length mod 64 == 56
    pad_len = (56 - (len(padded) % 64)) % 64
    padded.extend(b"\x00" * pad_len)

    # Append 64-bit length
    padded.extend(orig_bit_len.to_bytes(8, byteorder="big"))
    return bytes(padded)


def sha256_compress(h_state: List[int], block: bytes) -> List[int]:
    """Compress a single 64-byte block into the hash state."""
    # Step 1: Prepare the 64-word message schedule
    w = [0] * 64
    for t in range(16):
        w[t] = int.from_bytes(block[t * 4 : (t + 1) * 4], byteorder="big")

    for t in range(16, 64):
        s0 = small_sigma0(w[t - 15])
        s1 = small_sigma1(w[t - 2])
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & MASK_32

    # Step 2: Initialize working variables
    a, b, c, d, e, f, g, h = h_state

    # Step 3: Main compression loop (64 rounds)
    for t in range(64):
        t1 = (h + big_sigma1(e) + ch(e, f, g) + ROUND_CONSTANTS_K[t] + w[t]) & MASK_32
        t2 = (big_sigma0(a) + maj(a, b, c)) & MASK_32
        h = g
        g = f
        f = e
        e = (d + t1) & MASK_32
        d = c
        c = b
        b = a
        a = (t1 + t2) & MASK_32

    # Step 4: Compute the intermediate hash state
    return [
        (h_state[0] + a) & MASK_32,
        (h_state[1] + b) & MASK_32,
        (h_state[2] + c) & MASK_32,
        (h_state[3] + d) & MASK_32,
        (h_state[4] + e) & MASK_32,
        (h_state[5] + f) & MASK_32,
        (h_state[6] + g) & MASK_32,
        (h_state[7] + h) & MASK_32,
    ]


def sha256(data: bytes) -> bytes:
    """Compute the 256-bit SHA-256 digest of arbitrary bytes."""
    padded = pad_message(data)
    h_state = list(INITIAL_HASH_H)

    for i in range(0, len(padded), 64):
        chunk = padded[i : i + 64]
        h_state = sha256_compress(h_state, chunk)

    # Convert state to 32-byte digest
    digest = bytearray()
    for word in h_state:
        digest.extend(word.to_bytes(4, byteorder="big"))
    return bytes(digest)


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 and return hex string."""
    return sha256(data).hex()
