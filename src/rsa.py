"""
RSA (Rivest-Shamir-Adleman) from first principles.
Author: TRAN HUU QUYET (SID: 066206014296)
"""

from typing import Tuple
from math_utils import egcd, mod_inverse, pow_mod, generate_prime


def generate_rsa_keypair(bits: int = 1024, e: int = 65537) -> Tuple[Tuple[int, int], Tuple[int, int], Tuple[int, int]]:
    """
    Generate RSA public key (e, n) and private key (d, n).
    Guarantees exact bit length for modulus n.
    Returns: ((e, n), (d, n), (p, q))
    """
    half_bits = bits // 2
    while True:
        p = generate_prime(half_bits)
        q = generate_prime(half_bits)
        if p != q:
            n = p * q
            # Ensure n has the exact target bit length (reject 1023-bit moduli)
            if n.bit_length() != bits:
                continue
            phi = (p - 1) * (q - 1)
            g, _, _ = egcd(e, phi)
            if g == 1:
                d = mod_inverse(e, phi)
                return (e, n), (d, n), (p, q)


def rsa_encrypt(message_int: int, pub_key: Tuple[int, int]) -> int:
    """c = m^e mod n"""
    e, n = pub_key
    if message_int >= n:
        raise ValueError("Message integer must be less than modulus n")
    return pow_mod(message_int, e, n)


def rsa_decrypt(ciphertext_int: int, priv_key: Tuple[int, int]) -> int:
    """m = c^d mod n"""
    d, n = priv_key
    if ciphertext_int >= n:
        raise ValueError("Ciphertext integer must be less than modulus n")
    return pow_mod(ciphertext_int, d, n)


def encrypt_string(text: str, pub_key: Tuple[int, int]) -> int:
    """Encodes a short text string into an integer and encrypts it."""
    data_bytes = text.encode("utf-8")
    m = int.from_bytes(data_bytes, "big")
    return rsa_encrypt(m, pub_key)


def decrypt_string(ciphertext_int: int, priv_key: Tuple[int, int]) -> str:
    """Decrypts ciphertext integer and decodes back to UTF-8 text."""
    m = rsa_decrypt(ciphertext_int, priv_key)
    byte_len = (m.bit_length() + 7) // 8
    data_bytes = m.to_bytes(byte_len, "big")
    return data_bytes.decode("utf-8", errors="replace")


def small_worked_example():
    """
    Small worked example for Section 1.6:
    Let p = 61, q = 53
    """
    p, q = 61, 53
    n = p * q            # 3233
    phi = (p - 1) * (q - 1)  # 3120
    e = 17               # gcd(17, 3120) = 1
    d = mod_inverse(e, phi)  # 2753
    
    # Message m = 65 ('A')
    m = 65
    c = pow_mod(m, e, n)
    dec = pow_mod(c, d, n)
    return {
        "p": p, "q": q, "n": n, "phi": phi,
        "e": e, "d": d, "m": m, "c": c, "decrypted": dec
    }
