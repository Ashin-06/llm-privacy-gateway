"""Reversible tokenisation.

Each sensitive value is swapped for a placeholder such as `[[PAN_1]]` that is stable
within a conversation, so the model can still reason ("the customer's PAN [[PAN_1]]
matches the one on file"). The originals are kept encrypted (AES-256-GCM) in the
vault, keyed per conversation, and are only put back for callers whose role allows it.
"""
from __future__ import annotations

import base64
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PLACEHOLDER = re.compile(r"\[\[([A-Z_]+)_(\d+)(?::([^\]]{1,12}))?\]\]")


def _key() -> bytes:
    k = os.environ.get("PRIVGATE_VAULT_KEY")
    return base64.b64decode(k) if k else AESGCM.generate_key(bit_length=256)


@dataclass
class Conversation:
    created: float = field(default_factory=time.time)
    by_value: dict[tuple[str, str], str] = field(default_factory=dict)  # (type, normalised value) -> placeholder
    sealed: dict[str, bytes] = field(default_factory=dict)  # placeholder -> nonce + ciphertext
    counters: dict[str, int] = field(default_factory=dict)


class Vault:
    def __init__(self, ttl_seconds: float = 3600.0, key: bytes | None = None):
        self.aead = AESGCM(key or _key())
        self.ttl = ttl_seconds
        self.convs: dict[str, Conversation] = {}
        self._lock = threading.Lock()

    def _conv(self, cid: str) -> Conversation:
        now = time.time()
        with self._lock:
            for k in [k for k, c in self.convs.items() if now - c.created > self.ttl]:
                del self.convs[k]  # expired mappings are unrecoverable by design
            return self.convs.setdefault(cid, Conversation())

    @staticmethod
    def _norm(kind: str, value: str) -> str:
        return re.sub(r"[\s-]", "", value).upper() if kind not in ("PERSON", "EMAIL") else value.strip().lower()

    def tokenize(self, cid: str, kind: str, value: str, hint: str = "") -> str:
        c = self._conv(cid)
        key = (kind, self._norm(kind, value))
        with self._lock:
            if key in c.by_value:
                return c.by_value[key]
            c.counters[kind] = c.counters.get(kind, 0) + 1
            ph = f"[[{kind}_{c.counters[kind]}{':' + hint if hint else ''}]]"
            nonce = secrets.token_bytes(12)
            c.sealed[ph] = nonce + self.aead.encrypt(nonce, value.encode(), f"{cid}|{ph}".encode())
            c.by_value[key] = ph
            return ph

    def reveal(self, cid: str, placeholder: str) -> str | None:
        c = self.convs.get(cid)
        if c is None or placeholder not in c.sealed:
            return None
        blob = c.sealed[placeholder]
        return self.aead.decrypt(blob[:12], blob[12:], f"{cid}|{placeholder}".encode()).decode()

    def forget(self, cid: str) -> None:
        with self._lock:
            self.convs.pop(cid, None)
