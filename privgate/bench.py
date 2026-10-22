"""Detection benchmark on generated banking support text.

Each document is built from templates (support tickets, chat logs, call notes, KYC
emails) with labelled spans. Real-format identifiers carry valid check digits; the
hard negatives look the same but are not identifiers (order ids, UTRs, tracking
numbers, timestamps, amounts). A naive regex detector is scored on the same corpus to
show what validation buys.
"""
from __future__ import annotations

import random
import re
import string
from collections import defaultdict

from .checksums import gstin_check_char, luhn_digit, verhoeff_digit
from .detect import detect

FIRST = ["Priya", "Rahul", "Ananya", "Vikram", "Sneha", "Arjun", "Kavya", "Rohan", "Meera", "Aditya", "Fatima", "Joseph"]
LAST = ["Sharma", "Iyer", "Reddy", "Khan", "Patel", "Nair", "Gupta", "Das", "Singh", "Fernandes", "Rao", "Menon"]
HANDLES = ["okaxis", "oksbi", "ybl", "paytm", "okhdfcbank", "ibl", "axl"]


def aadhaar(r):
    base = str(r.randint(2, 9)) + "".join(r.choices(string.digits, k=10))
    d = base + verhoeff_digit(base)
    return r.choice([d, f"{d[:4]} {d[4:8]} {d[8:]}", f"{d[:4]}-{d[4:8]}-{d[8:]}"])


def card(r):
    prefix = r.choice(["4", "51", "52", "55", "60", "65", "508"])
    base = prefix + "".join(r.choices(string.digits, k=15 - len(prefix)))
    d = base + luhn_digit(base)
    return r.choice([d, " ".join(d[i:i + 4] for i in range(0, 16, 4)), "-".join(d[i:i + 4] for i in range(0, 16, 4))])


def pan(r):
    return "".join(r.choices(string.ascii_uppercase, k=3)) + r.choice("PCHF") + r.choice(string.ascii_uppercase) + \
        "".join(r.choices(string.digits, k=4)) + r.choice(string.ascii_uppercase)


def gstin(r):
    first = f"{r.randint(1, 37):02d}" + pan(r) + str(r.randint(1, 9)) + "Z"
    return first + gstin_check_char(first)


def phone(r):
    n = str(r.choice("6789")) + "".join(r.choices(string.digits, k=9))
    return r.choice([n, f"+91 {n[:5]} {n[5:]}", f"+91-{n}", f"0{n}"])


def name(r):
    return f"{r.choice(FIRST)} {r.choice(LAST)}"


def invalid_aadhaar_like(r):
    while True:
        base = str(r.randint(2, 9)) + "".join(r.choices(string.digits, k=11))
        if verhoeff_digit(base[:11]) != base[11]:
            return base


def invalid_card_like(r):
    base = "4" + "".join(r.choices(string.digits, k=14))
    good = luhn_digit(base)
    return base + str((int(good) + r.randint(1, 9)) % 10)


TEMPLATES = [
    "Ticket #{tid}: Customer name: {PERSON} called about a failed IMPS. Debited from a/c {ACCOUNT}, UTR {utr}. Callback on {PHONE}.",
    "KYC update for Mr. {PERSON}: PAN {PAN}, Aadhaar {AADHAAR}. Email {EMAIL}. Order id {order} is unrelated.",
    "Chat log 14:32 - user says card {CARD} was charged twice for Rs 2,499. Tracking no {tracking}. Asked to share OTP {OTP}, agent refused.",
    "Dispute: beneficiary {PERSON}, account no {ACCOUNT} IFSC {IFSC}, UPI {UPI_ID}. Amount 45,000 on 12/10/2026 10:41.",
    "Merchant onboarding: GSTIN {GSTIN}, contact {EMAIL}, phone {PHONE}. Settlement ref {utr}.",
    "Call note: Smt. {PERSON} (DOB {DOB}) reports Aadhaar {AADHAAR} misuse; mobile {PHONE}. Case {order}.",
    "Chargeback for card ending in 4421, full number {CARD}, CVV {CVV}. Reference {tracking}.",
    "Loan file: applicant {PERSON}, PAN {PAN}, salary credited to account {ACCOUNT}. Request id {order}.",
    "Refund of 1,250 sent to {UPI_ID} on 2026-10-18 09:15:42, txn {utr}.",
    "Hi team, invoice 2026-000123456 for 3,499,000 paise, PO 450012345678. No customer data here.",
]


def corpus(n: int = 600, seed: int = 0) -> list[tuple[str, list[tuple[int, int, str]]]]:
    r = random.Random(seed)
    docs = []
    for _ in range(n):
        tpl = r.choice(TEMPLATES)
        gens = {
            "PERSON": name(r), "PAN": pan(r), "AADHAAR": aadhaar(r), "CARD": card(r), "PHONE": phone(r),
            "EMAIL": f"{r.choice(FIRST).lower()}.{r.choice(LAST).lower()}{r.randint(1, 99)}@{r.choice(['gmail.com', 'yahoo.co.in', 'outlook.com'])}",
            "ACCOUNT": "".join(r.choices(string.digits, k=r.choice([11, 12, 14, 15, 16]))),
            "IFSC": r.choice(["HDFC", "ICIC", "SBIN", "UTIB", "KKBK"]) + "0" + "".join(r.choices(string.digits, k=6)),
            "UPI_ID": f"{r.choice(FIRST).lower()}{r.randint(1, 999)}@{r.choice(HANDLES)}", "GSTIN": gstin(r),
            "OTP": str(r.randint(100000, 999999)), "CVV": str(r.randint(100, 999)),
            "tid": str(r.randint(10000, 99999)), "utr": invalid_aadhaar_like(r), "order": invalid_aadhaar_like(r),
            "tracking": invalid_card_like(r), "DOB": f"{r.randint(1, 28):02d}/{r.randint(1, 12):02d}/{r.randint(1940, 2004)}",
        }
        text, spans, pos = "", [], 0
        for m in re.finditer(r"\{(\w+)\}", tpl):
            text += tpl[pos:m.start()]
            val = gens[m.group(1)]
            if m.group(1).isupper():
                spans.append((len(text), len(text) + len(val), m.group(1)))
            text += val
            pos = m.end()
        text += tpl[pos:]
        docs.append((text, spans))
    return docs


def naive(text: str) -> list[tuple[int, int, str]]:
    """What a typical first attempt looks like: lengths and shapes, no validation."""
    out = []
    for m in re.finditer(r"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)", text):
        out.append((m.start(), m.end(), "AADHAAR"))
    for m in re.finditer(r"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)", text):
        out.append((m.start(), m.end(), "CARD"))
    for m in re.finditer(r"(?<!\d)\d{9,18}(?!\d)", text):
        out.append((m.start(), m.end(), "ACCOUNT"))
    for m in re.finditer(r"\b[A-Z]{5}\d{4}[A-Z]\b", text):
        out.append((m.start(), m.end(), "PAN"))
    return out


def score(pred_fn, docs) -> dict[str, dict]:
    tp, fp, fn = defaultdict(int), defaultdict(int), defaultdict(int)
    for text, gold in docs:
        pred = set(pred_fn(text))
        g = set(gold)
        for s, e, t in pred:
            hit = any(t == gt and s < ge and gs < e for gs, ge, gt in g)
            (tp if hit else fp)[t] += 1
        for gs, ge, gt in g:
            if not any(t == gt and s < ge and gs < e for s, e, t in pred):
                fn[gt] += 1
    out = {}
    for t in sorted(set(tp) | set(fp) | set(fn)):
        p = tp[t] / max(tp[t] + fp[t], 1)
        r = tp[t] / max(tp[t] + fn[t], 1)
        out[t] = {"precision": p, "recall": r, "f1": 2 * p * r / max(p + r, 1e-9), "support": tp[t] + fn[t]}
    return out


def run(n: int = 600, seed: int = 0) -> dict:
    docs = corpus(n, seed)
    ours = score(lambda t: [(e.start, e.end, e.type) for e in detect(t)], docs)
    base = score(naive, docs)
    return {"gateway": ours, "naive_regex": base}
