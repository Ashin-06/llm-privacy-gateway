"""Reversible tokenisation.

Each sensitive value is swapped for a placeholder such as `[[PAN_1]]` that is stable
within a conversation, so the model can still reason ("the customer's PAN [[PAN_1]]
matches the one on file"). The originals are kept encrypted (AES-256-GCM) in the
vault, keyed per conversation, and are only put back for callers whose role allows it.

The vault lives in the database (see db.py), so placeholders survive restarts and work
across replicas that share PRIVGATE_VAULT_KEY. Only ciphertext and an HMAC lookup are
stored, never the value.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
import secrets
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from . import db

PLACEHOLDER = re.compile(r"\[\[([A-Z_]+)_(\d+)(?::([^\]]{1,12}))?\]\]")
log = logging.getLogger("privgate.vault")


class Vault:
    def __init__(self, ttl_seconds: float = 3600.0, key: bytes | None = None, engine: Engine | None = None,
                 previous_keys: tuple[bytes, ...] = ()):
        key = key or AESGCM.generate_key(bit_length=256)
        self.aead = AESGCM(key)
        self.old = [AESGCM(k) for k in previous_keys]  # still readable while rotating
        self.lookup_key = hashlib.sha256(b"privgate-lookup|" + key).digest()
        self.ttl = ttl_seconds
        self.db = engine or db.connect("sqlite://")
        self._lock = threading.Lock()  # ponytail: per process; other replicas are caught by the table keys

    @staticmethod
    def _norm(kind: str, value: str) -> str:
        return re.sub(r"[\s-]", "", value).upper() if kind not in ("PERSON", "EMAIL") else value.strip().lower()

    def _conv(self, c, cid: str) -> None:
        """Drop expired conversations (their mappings become unrecoverable by design), then make sure cid exists."""
        cutoff = int(time.time() - self.ttl)
        old = [r[0] for r in c.execute(text("SELECT id FROM conversations WHERE created_at < :t"), {"t": cutoff})]
        for o in old:
            c.execute(text("DELETE FROM vault_entries WHERE conversation_id = :c"), {"c": o})
            c.execute(text("DELETE FROM conversations WHERE id = :c"), {"c": o})
        if c.execute(text("SELECT 1 FROM conversations WHERE id = :c"), {"c": cid}).first() is None:
            c.execute(text("INSERT INTO conversations (id, owner, created_at) VALUES (:c, NULL, :t)"),
                      {"c": cid, "t": int(time.time())})

    def tokenize(self, cid: str, kind: str, value: str, hint: str = "") -> str:
        lookup = hmac.new(self.lookup_key, f"{cid}|{kind}|{self._norm(kind, value)}".encode(), hashlib.sha256).hexdigest()
        for attempt in range(3):
            try:
                with self._lock, self.db.begin() as c:
                    self._conv(c, cid)
                    row = c.execute(text("SELECT placeholder FROM vault_entries WHERE conversation_id = :c AND lookup = :l"),
                                    {"c": cid, "l": lookup}).first()
                    if row:
                        return row[0]
                    n = c.execute(text("SELECT COUNT(*) FROM vault_entries WHERE conversation_id = :c AND kind = :k"),
                                  {"c": cid, "k": kind}).scalar() + 1
                    ph = f"[[{kind}_{n}{':' + hint if hint else ''}]]"
                    nonce = secrets.token_bytes(12)
                    sealed = base64.b64encode(nonce + self.aead.encrypt(nonce, value.encode(), f"{cid}|{ph}".encode())).decode()
                    c.execute(text("INSERT INTO vault_entries (conversation_id, placeholder, kind, lookup, sealed) "
                                   "VALUES (:c, :p, :k, :l, :s)"), {"c": cid, "p": ph, "k": kind, "l": lookup, "s": sealed})
                    return ph
            except IntegrityError:  # another replica took the same number; read again
                if attempt == 2:
                    raise
        raise AssertionError("unreachable")

    def claim(self, cid: str, user: str | None) -> bool:
        """Bind a conversation to its first user. Returns False if someone else owns it."""
        with self._lock, self.db.begin() as c:
            self._conv(c, cid)
            c.execute(text("UPDATE conversations SET owner = :u WHERE id = :c AND owner IS NULL"), {"u": user, "c": cid})
            owner = c.execute(text("SELECT owner FROM conversations WHERE id = :c"), {"c": cid}).scalar()
        return user is None or owner in (None, user)

    def owner(self, cid: str) -> str | None:
        with self.db.connect() as c:
            return c.execute(text("SELECT owner FROM conversations WHERE id = :c"), {"c": cid}).scalar()

    def reveal(self, cid: str, placeholder: str) -> str | None:
        with self.db.connect() as c:
            blob = c.execute(text("SELECT sealed FROM vault_entries WHERE conversation_id = :c AND placeholder = :p"),
                             {"c": cid, "p": placeholder}).scalar()
        if blob is None:
            return None
        raw = base64.b64decode(blob)
        for aead in [self.aead, *self.old]:
            try:
                return aead.decrypt(raw[:12], raw[12:], f"{cid}|{placeholder}".encode()).decode()
            except InvalidTag:
                continue
        log.warning("vault entry sealed with a key that is no longer configured")
        return None

    def forget(self, cid: str) -> None:
        with self._lock, self.db.begin() as c:
            c.execute(text("DELETE FROM vault_entries WHERE conversation_id = :c"), {"c": cid})
            c.execute(text("DELETE FROM conversations WHERE id = :c"), {"c": cid})
