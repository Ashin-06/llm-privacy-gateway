"""Detection on Gretel's labelled financial documents.

Real customer identifiers cannot be published, so the closest public test is
gretelai/synthetic_pii_finance_multilingual (Apache-2.0): about 56,000 English financial
documents (loan applications, SWIFT messages, statements, insurance claims ...) written by an
LLM, with every PII span labelled by type. The text is realistic; the people are not real.
Most of it is US / European, while this gateway's checksums target Indian identifiers, so
some types are expected to be missed and are reported as such.

    python -m privgate realdata --gretel English_test-00000-of-00001.parquet
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pandas as pd

from .engine import Engine

# Gretel label -> the gateway type that should catch it
TARGET = {
    "name": "PERSON", "first_name": "PERSON", "last_name": "PERSON",
    "email": "EMAIL", "phone_number": "PHONE",
    "credit_card_number": "CARD", "credit_card_security_code": "CVV", "account_pin": "OTP",
    "bban": "ACCOUNT", "iban": "ACCOUNT", "passport_number": "PASSPORT", "date_of_birth": "DOB",
    "password": "SECRET", "api_key": "SECRET",
}
# present in the data but outside what the gateway is built to find
NOT_TARGETED = ("ssn", "driver_license_number", "street_address", "company", "customer_id", "employee_id",
                "swift_bic_code", "bank_routing_number", "ipv4", "ipv6", "user_name", "date", "date_time", "time", "local_latlng")


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def run(path: str | Path, limit: int | None = None) -> dict:
    df = pd.read_parquet(path)
    if "language" in df:
        df = df[df["language"] == "English"]
    df = df.head(limit) if limit else df
    eng = Engine()
    per = defaultdict(lambda: {"gold": 0, "masked": 0, "typed_right": 0})
    detections = on_pii = 0
    blocked_docs = 0
    for text, spans in zip(df["generated_text"], df["pii_spans"]):
        gold = [(s["start"], s["end"], s["label"]) for s in json.loads(spans)]
        found = [e for e in eng.scan(text) if eng.action(e.type) != "allow"]
        blocked_docs += any(eng.action(e.type) == "block" for e in found)
        for g0, g1, label in gold:
            hits = [e for e in found if _overlaps((g0, g1), (e.start, e.end))]
            r = per[label]
            r["gold"] += 1
            r["masked"] += bool(hits)
            r["typed_right"] += any(e.type == TARGET.get(label) for e in hits)
        for e in found:
            detections += 1
            on_pii += any(_overlaps((e.start, e.end), (g0, g1)) for g0, g1, _ in gold)

    rows = {lab: {**r, "target_type": TARGET.get(lab), "masked_share": round(r["masked"] / r["gold"], 3)}
            for lab, r in sorted(per.items(), key=lambda kv: -kv[1]["gold"])}
    targeted = [r for lab, r in rows.items() if lab in TARGET]
    return {
        "dataset": "gretelai/synthetic_pii_finance_multilingual, English" + (f" (first {limit})" if limit else ""),
        "documents": int(len(df)),
        "targeted_spans_masked": round(sum(r["masked"] for r in targeted) / max(sum(r["gold"] for r in targeted), 1), 3),
        "detections_on_a_labelled_span": round(on_pii / max(detections, 1), 3),
        "documents_that_would_be_refused": int(blocked_docs),
        "note": ("masked = the span overlaps something the gateway tokenises, redacts or blocks; the last-but-one figure "
                 "is a lower bound on precision because the labels can miss PII"),
        "by_label": rows,
        "not_targeted_labels": [lab for lab in NOT_TARGETED if lab in rows],
    }
