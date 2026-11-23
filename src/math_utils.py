# Custom number-theoretic routines for student TRAN HUU QUYET
# SID: 066206014296 - Information Security Project

import secrets
from typing import Tuple, Optional


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.
    Computes gcd(a, b) and Bézout coefficients (x, y) such that a*x + b*y = gcd(a, b).
    Returns: (gcd, x, y)
    """
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def mod_inverse(a: int, m: int) -> int:
    """
    Modular Multiplicative Inverse.
    Computes x such that a * x = 1 (mod m).
    Raises ValueError if gcd(a, m) != 1.
    """
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def pow_mod(base: int, exp: int, mod: int) -> int:
    """
    Square-and-Multiply Modular Exponentiation.
    Computes (base^exp) mod mod efficiently in O(log exp) time.
    Handles negative exponents via modular inverse.
    """
    if mod <= 0:
        raise ValueError("Modulus must be positive")
    if mod == 1:
        return 0
    if exp < 0:
        base = mod_inverse(base, mod)
        exp = -exp
    res = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            res = (res * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return res


def is_prime_miller_rabin(n: int, rounds: int = 40) -> bool:
    """
    Miller-Rabin Probabilistic Primality Test.
    Performs 'rounds' independent witness tests using cryptographically secure random bases.
    Error probability <= 4^(-rounds) <= 4^(-40) < 10^(-24).
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow_mod(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = pow_mod(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True


def generate_prime(bit_length: int) -> int:
    """
    Generate a probable prime of exact bit_length using cryptographically secure entropy.
    """
    if bit_length < 2:
        raise ValueError("Prime bit length must be at least 2")
    while True:
        candidate = (secrets.randbits(bit_length) | (1 << (bit_length - 1))) | 1
        if is_prime_miller_rabin(candidate):
            return candidate


def bytes_to_int(b: bytes) -> int:
    """Convert big-endian bytes to unsigned integer."""
    return int.from_bytes(b, "big")


def int_to_bytes(val: int, length: Optional[int] = None) -> bytes:
    """Convert unsigned integer to big-endian bytes."""
    if length is None:
        length = (val.bit_length() + 7) // 8 or 1
    return val.to_bytes(length, "big")
