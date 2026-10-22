"""Detectors for personal and secret data in free text, tuned for Indian banking.

Every numeric identifier is validated, not just pattern-matched: Aadhaar needs a
valid Verhoeff check digit, cards a valid Luhn digit and a known network prefix,
GSTIN its mod-36 check character, PAN a valid holder-type letter. Bank account numbers
have no checksum, so they are only taken when account context is nearby.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .checksums import card_network, gstin_valid, luhn_valid, verhoeff_valid

UPI_HANDLES = {"okaxis", "oksbi", "okhdfcbank", "okicici", "ybl", "ibl", "axl", "paytm", "ptsbi", "pthdfc", "ptaxis",
               "ptyes", "upi", "apl", "yapl", "ikwik", "freecharge", "airtel", "jio", "kotak", "hdfcbank", "icici", "sbi",
               "axisbank", "yesbank", "idfcbank", "indus", "federal", "pnb", "barodampay", "boi", "cnrb", "aubank", "rbl"}
PAN_HOLDER = set("PCHFATBLJG")


@dataclass(frozen=True)
class Entity:
    type: str
    start: int
    end: int
    value: str
    confidence: float
    note: str = ""


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _context(text: str, start: int, end: int, words: str, window: int = 40) -> bool:
    around = text[max(0, start - window) : min(len(text), end + window)].lower()
    return re.search(words, around) is not None


AADHAAR = re.compile(r"(?<![\d-])([2-9]\d{3})[ -]?(\d{4})[ -]?(\d{4})(?![\d-])")
CARD = re.compile(r"(?<!\d)(\d(?:[ -]?\d){12,18})(?!\d)")
PAN = re.compile(r"\b([A-Z]{3})([A-Z])([A-Z])(\d{4})([A-Z])\b")
GSTIN = re.compile(r"\b(\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z])\b")
IFSC = re.compile(r"\b([A-Z]{4}0[A-Z0-9]{6})\b")
ACCOUNT = re.compile(r"(?<![\d-])(\d{9,18})(?![\d-])")
PHONE = re.compile(r"(?<![\d+])(?:\+91[\s-]?|91[\s-]|0)?([6-9]\d{4}[\s-]?\d{5})(?!\d)")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
VPA = re.compile(r"\b([a-zA-Z0-9.\-_]{2,64})@([a-zA-Z]{2,30})\b(?!\.[a-zA-Z])")
PASSPORT = re.compile(r"\b([A-PR-WY][1-9]\d\s?\d{4}[1-9])\b")
VOTER = re.compile(r"\b([A-Z]{3}\d{7})\b")
DOB = re.compile(r"\b(?:dob|date of birth|born on)\W{0,3}(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{1,2} \w{3,9} \d{4})", re.I)
_GLUE = r"(?:\W|\bis\b|\bwas\b|\bcode\b|\bnumber\b|\bno\b){0,12}?"  # "otp is 4829", "cvv code: 123"
CVV = re.compile(rf"\b(?:cvv|cvc|cvv2){_GLUE}(\d{{3,4}})\b", re.I)
OTP = re.compile(rf"\b(?:otp|one[- ]time password|pin){_GLUE}(\d{{4,8}})\b", re.I)
NAME = re.compile(r"\b(?:Mr|Mrs|Ms|Miss|Dr|Shri|Smt|Kumari)\.?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})")
NAME_FIELD = re.compile(r"\b(?:customer name|account holder|name|beneficiary|applicant|payee|nominee|customer)\s*[:=-]?\s*"
                        r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})")  # two to four capitalised words
SECRETS = [
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("api_key", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b|\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("password", re.compile(r"(?i)\b(?:password|passwd|pwd|mpin)\s*[:=]\s*(\S{4,})")),
]
ACCOUNT_WORDS = re.compile(r"(a/c|\bac\b|acc(ou)?n?t|acct|account( no| number)?|savings|beneficiary|credited to|debited from|neft to|imps to)", re.I)
OTHER_LABELS = re.compile(r"\b(utr|ref(erence)?|order|txn|transaction|po|case|request|ticket|tracking|invoice|id|no\.? of|callback|call|mobile|phone|ph|tel|contact|otp|pin|cvv)\b", re.I)


def _account_label_before(text: str, start: int) -> bool:
    """True when the closest label before the number is an account label."""
    before = text[max(0, start - 30) : start]
    acc = [m.end() for m in ACCOUNT_WORDS.finditer(before)]
    other = [m.end() for m in OTHER_LABELS.finditer(before)]
    return bool(acc) and (not other or max(acc) > max(other))


def detect(text: str, extra: dict[str, re.Pattern] | None = None) -> list[Entity]:
    found: list[Entity] = []

    for m in AADHAAR.finditer(text):
        d = _digits(m.group(0))
        if verhoeff_valid(d):
            found.append(Entity("AADHAAR", m.start(), m.end(), m.group(0), 0.97, "Verhoeff check digit valid"))
        elif _context(text, m.start(), m.end(), r"aadh?aa?r|uidai"):
            found.append(Entity("AADHAAR", m.start(), m.end(), m.group(0), 0.6, "labelled as Aadhaar, check digit invalid"))
    for m in CARD.finditer(text):
        d = _digits(m.group(1))
        if 13 <= len(d) <= 19 and luhn_valid(d) and card_network(d):
            found.append(Entity("CARD", m.start(1), m.end(1), m.group(1), 0.98, f"{card_network(d)}, Luhn valid"))
    for m in CVV.finditer(text):
        found.append(Entity("CVV", m.start(1), m.end(1), m.group(1), 0.95))
    for m in PAN.finditer(text):
        if m.group(2) in PAN_HOLDER:
            found.append(Entity("PAN", m.start(), m.end(), m.group(0), 0.95, f"holder type {m.group(2)}"))
    for m in GSTIN.finditer(text):
        if gstin_valid(m.group(1)):
            found.append(Entity("GSTIN", m.start(), m.end(), m.group(1), 0.97, "check character valid"))
    for m in IFSC.finditer(text):
        found.append(Entity("IFSC", m.start(), m.end(), m.group(1), 0.9))
    for m in PASSPORT.finditer(text):
        if _context(text, m.start(), m.end(), r"passport"):
            found.append(Entity("PASSPORT", m.start(), m.end(), m.group(1), 0.85))
    for m in VOTER.finditer(text):
        if _context(text, m.start(), m.end(), r"voter|epic|election"):
            found.append(Entity("VOTER_ID", m.start(), m.end(), m.group(1), 0.85))
    for m in EMAIL.finditer(text):
        found.append(Entity("EMAIL", m.start(), m.end(), m.group(0), 0.97))
    for m in VPA.finditer(text):
        if m.group(2).lower() in UPI_HANDLES:
            found.append(Entity("UPI_ID", m.start(), m.end(), m.group(0), 0.95))
    for m in PHONE.finditer(text):
        found.append(Entity("PHONE", m.start(), m.end(), m.group(0), 0.85))
    for m in ACCOUNT.finditer(text):
        if _account_label_before(text, m.start()):
            found.append(Entity("ACCOUNT", m.start(), m.end(), m.group(1), 0.8, "account context nearby"))
    for m in DOB.finditer(text):
        found.append(Entity("DOB", m.start(1), m.end(1), m.group(1), 0.9))
    for m in OTP.finditer(text):
        found.append(Entity("OTP", m.start(1), m.end(1), m.group(1), 0.9))
    for rx in (NAME, NAME_FIELD):
        for m in rx.finditer(text):
            found.append(Entity("PERSON", m.start(1), m.end(1), m.group(1), 0.75))
    for kind, rx in SECRETS:
        for m in rx.finditer(text):
            g = m.lastindex and kind == "password"
            s, e = (m.start(1), m.end(1)) if g else (m.start(), m.end())
            found.append(Entity("SECRET", s, e, text[s:e], 0.99, kind))
    for name, rx in (extra or {}).items():
        for m in rx.finditer(text):
            found.append(Entity(name, m.start(), m.end(), m.group(0), 0.9, "custom pattern"))
    return resolve(found)


PRIORITY = {"SECRET": 0, "CARD": 1, "AADHAAR": 2, "CVV": 3, "OTP": 3, "GSTIN": 4, "PAN": 5, "UPI_ID": 6, "EMAIL": 7,
            "PASSPORT": 8, "VOTER_ID": 8, "IFSC": 9, "ACCOUNT": 10, "PHONE": 11, "DOB": 12, "PERSON": 13}


def resolve(found: list[Entity]) -> list[Entity]:
    """Keep the best entity when spans overlap (a valid card beats a 'phone' inside it)."""
    ranked = sorted(found, key=lambda e: (PRIORITY.get(e.type, 50), -e.confidence, -(e.end - e.start)))
    taken: list[Entity] = []
    for e in ranked:
        if all(e.end <= t.start or e.start >= t.end for t in taken):
            taken.append(e)
    return sorted(taken, key=lambda e: e.start)
