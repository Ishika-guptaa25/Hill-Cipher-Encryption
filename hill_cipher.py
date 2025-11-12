# hill_cipher.py
# Pure Python implementation of Hill Cipher (supports any n x n key).
# Author: ChatGPT (example). Use in PyCharm or anywhere.

from typing import List, Tuple
import math
import string

ALPHABET = string.ascii_uppercase
MOD = 26

# ---------------- helper math ----------------

def egcd(a: int, b: int) -> Tuple[int,int,int]:
    """Extended GCD: returns (g, x, y) such that a*x + b*y = g = gcd(a,b)"""
    if b == 0:
        return (a, 1, 0)
    else:
        g, x1, y1 = egcd(b, a % b)
        return (g, y1, x1 - (a // b) * y1)

def modinv(a: int, m: int) -> int:
    """Modular inverse of a under modulus m. Raises ValueError if none."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} modulo {m} (gcd={g})")
    return x % m

def matrix_mod(matrix: List[List[int]], m: int) -> List[List[int]]:
    return [[x % m for x in row] for row in matrix]

# ---------------- matrix helpers (pure python) ----------------

def matrix_minor(mat: List[List[int]], i: int, j: int) -> List[List[int]]:
    """Return minor matrix after removing row i and column j."""
    return [ [row[c] for c in range(len(mat)) if c != j] for r, row in enumerate(mat) if r != i ]

def determinant(mat: List[List[int]]) -> int:
    """Recursive determinant (integer)"""
    n = len(mat)
    if n == 1:
        return mat[0][0]
    if n == 2:
        return mat[0][0]*mat[1][1] - mat[0][1]*mat[1][0]
    det = 0
    for j in range(n):
        sign = -1 if (j % 2) else 1
        det += sign * mat[0][j] * determinant(matrix_minor(mat, 0, j))
    return det

def cofactor_matrix(mat: List[List[int]]) -> List[List[int]]:
    n = len(mat)
    cof = [[0]*n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            minor = determinant(matrix_minor(mat, i, j))
            cof[i][j] = ((-1) ** (i + j)) * minor
    return cof

def transpose(mat: List[List[int]]) -> List[List[int]]:
    return list(map(list, zip(*mat)))

def adjugate(mat: List[List[int]]) -> List[List[int]]:
    # adjugate = transpose of cofactor matrix
    return transpose(cofactor_matrix(mat))

def matrix_mul(A: List[List[int]], B: List[List[int]]) -> List[List[int]]:
    # Multiply matrices A (n x m) and B (m x p) -> result (n x p)
    n = len(A)
    m = len(A[0])
    p = len(B[0])
    result = [[0]*p for _ in range(n)]
    for i in range(n):
        for j in range(p):
            s = 0
            for k in range(m):
                s += A[i][k] * B[k][j]
            result[i][j] = s
    return result

def matrix_mul_mod(A: List[List[int]], B: List[List[int]], m: int) -> List[List[int]]:
    R = matrix_mul(A, B)
    return [[x % m for x in row] for row in R]

# ---------------- modular inverse of matrix ----------------

def matrix_mod_inv(mat: List[List[int]], m: int) -> List[List[int]]:
    """Return inverse of mat modulo m (mat must be square)."""
    n = len(mat)
    det = determinant(mat)
    det_mod = det % m
    try:
        det_inv = modinv(det_mod, m)
    except ValueError:
        raise ValueError(f"Matrix determinant {det} (mod {m} = {det_mod}) has no inverse -> key not invertible")
    adj = adjugate(mat)
    inv = [[(det_inv * adj[r][c]) % m for c in range(n)] for r in range(n)]
    return inv

# ---------------- text <-> numeric helpers ----------------

def clean_text(s: str, preserve_nonletters: bool=False) -> str:
    if preserve_nonletters:
        return s
    return ''.join(ch for ch in s.upper() if ch.isalpha())

def text_to_numbers(s: str) -> List[int]:
    return [ALPHABET.index(ch) for ch in s]

def numbers_to_text(nums: List[int]) -> str:
    return ''.join(ALPHABET[n % MOD] for n in nums)

def chunk_list(lst: List[int], n: int, pad_value: int=0) -> List[List[int]]:
    out = []
    for i in range(0, len(lst), n):
        chunk = lst[i:i+n]
        if len(chunk) < n:
            chunk = chunk + [pad_value] * (n - len(chunk))
        out.append(chunk)
    return out

# ---------------- encryption / decryption ----------------

def encrypt(plaintext: str, key: List[List[int]], preserve_nonletters: bool=False, pad_char: str='X') -> str:
    # Clean text (remove non letters by default)
    raw = clean_text(plaintext, preserve_nonletters=False)  # Hill normally works on letters only
    n = len(key)
    nums = text_to_numbers(raw)
    pad_val = ALPHABET.index(pad_char.upper())
    blocks = chunk_list(nums, n, pad_val)
    cipher_nums = []
    for block in blocks:
        # convert block to column vector (n x 1)
        P = [[x] for x in block]
        C = matrix_mul_mod(key, P, MOD)  # result n x 1
        for row in C:
            cipher_nums.append(row[0] % MOD)
    return numbers_to_text(cipher_nums)

def decrypt(ciphertext: str, key: List[List[int]], preserve_nonletters: bool=False) -> str:
    raw = clean_text(ciphertext, preserve_nonletters=False)
    n = len(key)
    nums = text_to_numbers(raw)
    blocks = chunk_list(nums, n, pad_value=0)
    inv_key = matrix_mod_inv(key, MOD)
    plain_nums = []
    for block in blocks:
        C = [[x] for x in block]
        P = matrix_mul_mod(inv_key, C, MOD)
        for row in P:
            plain_nums.append(row[0] % MOD)
    return numbers_to_text(plain_nums)

# ---------------- utilities for user input key ----------------

def make_key_matrix_from_list(flat_list: List[int]) -> List[List[int]]:
    """Given length n^2 list, convert to n x n matrix. n inferred."""
    L = len(flat_list)
    n = int(math.sqrt(L))
    if n*n != L:
        raise ValueError("Flat list length must be a perfect square (n^2).")
    mat = []
    idx = 0
    for _ in range(n):
        row = []
        for _ in range(n):
            row.append(flat_list[idx])
            idx += 1
        mat.append(row)
    return mat

# ---------------- example usage ----------------
if __name__ == "__main__":
    # Example 2x2 key (classic)
    key_2x2 = [[3,3],[2,5]]
    pt = "HELLO"
    ct = encrypt(pt, key_2x2, pad_char='X')
    print("Plain :", pt)
    print("Cipher:", ct)
    print("Decrypted:", decrypt(ct, key_2x2))

    # Example 3x3 key (common teaching example)
    key_3x3 = [[6,24,1],[13,16,10],[20,17,15]]
    pt2 = "ACT"
    ct2 = encrypt(pt2, key_3x3)
    print("\nPlain :", pt2)
    print("Cipher:", ct2)
    print("Decrypted:", decrypt(ct2, key_3x3))
