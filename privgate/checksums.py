"""Check-digit algorithms used by Indian and payment identifiers. Validating the check
digit is what separates a real Aadhaar or card number from an order id that happens
to have the same length."""
from __future__ import annotations

# Verhoeff (Aadhaar)
_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_digit(digits: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def luhn_digit(digits: str) -> str:
    for d in "0123456789":
        if luhn_valid(digits + d):
            return d
    raise ValueError(digits)


_GST_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def gstin_check_char(first14: str) -> str:
    total = 0
    for i, ch in enumerate(first14):
        v = _GST_CHARS.index(ch) * (1 if i % 2 == 0 else 2)
        total += v // 36 + v % 36
    return _GST_CHARS[(36 - total % 36) % 36]


def gstin_valid(g: str) -> bool:
    return len(g) == 15 and all(c in _GST_CHARS for c in g) and gstin_check_char(g[:14]) == g[14]


def iban_valid(iban: str) -> bool:
    """ISO 13616 / ISO 7064 mod 97-10: move the first four characters to the end, letters
    become 10..35, and the whole number must leave remainder 1 when divided by 97."""
    s = iban.replace(" ", "").upper()
    if not (15 <= len(s) <= 34 and s[:2].isalpha() and s[2:4].isdigit() and s.isalnum()):
        return False
    return int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97 == 1


def card_network(digits: str) -> str | None:
    n = len(digits)
    if digits.startswith("4") and n in (13, 16, 19):
        return "visa"
    p2, p4 = int(digits[:2]), int(digits[:4])
    if n == 16 and (51 <= p2 <= 55 or 2221 <= p4 <= 2720):
        return "mastercard"
    if n == 15 and p2 in (34, 37):
        return "amex"
    if n == 16 and (digits.startswith(("60", "65", "81", "82", "508", "353", "356"))):
        return "rupay"
    if n == 14 and p2 in (36, 38, 39) or digits.startswith(("300", "301", "302", "303", "304", "305")):
        return "diners"
    return None
