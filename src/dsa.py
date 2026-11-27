"""
DSA (Digital Signature Algorithm) from first principles.
Author: TRAN HUU QUYET (SID: 066206014296)
Following NIST FIPS 186-4 standard.
"""

import secrets
from typing import Tuple, Dict, Any
from math_utils import mod_inverse, pow_mod
from sha256 import sha256


# Standard NIST FIPS 186-4 verified domain parameters (L=1024, N=160)
# for fast, stable, and cryptographically verified execution
FIPS_1024_P = int(
    "0xFD7F53811D75122952DF4A9C2EECE4E7F611B7523CEF4400C31E3F80B6512669"
    "455D402251FB593D8D58FABFC5F5BA30F6CB9B556CD7813B801D346FF26660B7"
    "6B9950A5A49F9FE8047B1022C24FBBA9D7FEB7C61BF83B57E7C6A8A6150F04FB"
    "83F6D3C51EC3023554135A169132F675F3AE2B61D72AEFF22203199DD14801C7",
    16
)

FIPS_160_Q = int(
    "0x9760508F15230BCCB292B982A2EB840BF0581CF5",
    16
)

FIPS_1024_G = int(
    "0xF7E1A085D69B3DDECBBCAB5C36B857B97994AFBBFA3AEA82F9574C0B3D078267"
    "5159578EBAD4594FE67107108180B449167123E84C281613B7CF09328CC8A6E1"
    "3C167A8B547C8D28E0A3AE1E2BB3A675916EA37F0BFA213562F1FB627A01243B"
    "CCA4F1BEA8519089A883DFE15AE59F06928B665E807B552564014C3BFECF492A",
    16
)


def generate_dsa_keypair(
    p: int = FIPS_1024_P, q: int = FIPS_160_Q, g: int = FIPS_1024_G
) -> Tuple[int, int]:
    """
    Generate DSA private key x and public key y.
    Returns: (x, y) where x is in [1, q-1] and y = g^x mod p.
    """
    x = secrets.randbelow(q - 1) + 1
    y = pow_mod(g, x, p)
    return x, y


def _hash_to_int(message_bytes: bytes, q_bits: int) -> int:
    """Computes SHA-256 and converts the digest to an integer truncated to q_bits."""
    digest = sha256(message_bytes)
    h_int = int.from_bytes(digest, "big")
    digest_bits = len(digest) * 8
    if digest_bits > q_bits:
        h_int >>= (digest_bits - q_bits)
    return h_int


def dsa_sign(
    message: bytes,
    x: int,
    p: int = FIPS_1024_P,
    q: int = FIPS_160_Q,
    g: int = FIPS_1024_G,
) -> Tuple[int, int]:
    """
    Generate DSA signature (r, s) for a message.
    """
    if not (0 < x < q):
        raise ValueError("Private key x must satisfy 0 < x < q")
    q_bits = q.bit_length()
    z = _hash_to_int(message, q_bits)

    while True:
        k = secrets.randbelow(q - 1) + 1
        r = pow_mod(g, k, p) % q
        if r == 0:
            continue
        try:
            k_inv = mod_inverse(k, q)
        except ValueError:
            continue
        s = (k_inv * (z + x * r)) % q
        if s == 0:
            continue
        return r, s


def dsa_verify(
    message: bytes,
    signature: Tuple[int, int],
    y: int,
    p: int = FIPS_1024_P,
    q: int = FIPS_160_Q,
    g: int = FIPS_1024_G,
) -> bool:
    """
    Verify DSA signature (r, s) against public key y and domain parameters.
    """
    r, s = signature
    if not (1 < y < p) or not (0 < r < q and 0 < s < q):
        return False

    q_bits = q.bit_length()
    z = _hash_to_int(message, q_bits)

    w = mod_inverse(s, q)
    u1 = (z * w) % q
    u2 = (r * w) % q

    # Compute v = ((g^u1 * y^u2) mod p) mod q
    t1 = pow_mod(g, u1, p)
    t2 = pow_mod(y, u2, p)
    v = ((t1 * t2) % p) % q

    return v == r


def small_worked_example() -> Dict[str, Any]:
    """
    Small worked example for Section 1.6:
    Let p = 59, q = 29 (note: 29 | (59 - 1) = 58)
    g = 3^((59-1)/29) mod 59 = 3^2 mod 59 = 9
    """
    p = 59
    q = 29
    g = 9
    x = 7            # private key
    y = pow_mod(g, x, p)  # public key = 9^7 mod 59 = 16

    # Message hash integer z (assume pre-hashed value for pedagogical clarity)
    z = 15
    k = 10           # per-message secret nonce
    r = pow_mod(g, k, p) % q  # 9^10 mod 59 = 41, 41 % 29 = 12
    k_inv = mod_inverse(k, q) # 10^-1 mod 29 = 3 (since 10*3 = 30 = 1 mod 29)
    s = (k_inv * (z + x * r)) % q # (3 * (15 + 7 * 12)) % 29 = (3 * 99) % 29 = 297 % 29 = 7

    # Verification:
    w = mod_inverse(s, q)    # 7^-1 mod 29 = 25 (since 7 * 25 = 175 = 6 * 29 + 1)
    u1 = (z * w) % q         # (15 * 25) % 29 = 375 % 29 = 27
    u2 = (r * w) % q         # (12 * 25) % 29 = 300 % 29 = 10
    # v = ((9^27 * 16^10) mod 59) mod 29 = ((51 * 17) mod 59) mod 29 = 41 % 29 = 12
    v = ((pow_mod(g, u1, p) * pow_mod(y, u2, p)) % p) % q

    return {
        "p": p, "q": q, "g": g,
        "x": x, "y": y,
        "z": z, "k": k,
        "r": r, "s": s,
        "w": w, "u1": u1, "u2": u2, "v": v,
        "is_valid": (v == r)
    }
