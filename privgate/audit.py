"""Hash-chained audit log in the database. Entries hold counts and decisions, never the
sensitive values. Each entry carries an HMAC (PRIVGATE_AUDIT_KEY) over its body and the
previous entry's hash, so editing, deleting or reordering one breaks verification."""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from . import db
from .ops import DECISIONS


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


class Audit:
    GENESIS = "0" * 64

    def __init__(self, engine: Engine | None = None, key: bytes | None = None, previous_keys: tuple[bytes, ...] = ()):
        self.db = engine or db.connect("sqlite://")
        self.keys = [key] if key else []
        self.keys += list(previous_keys)  # entries written before a rotation still verify
        self._lock = threading.Lock()

    def _digest(self, body: dict, key: bytes | None) -> str:
        data = _canon(body)
        return hmac.new(key, data, hashlib.sha256).hexdigest() if key else hashlib.sha256(data).hexdigest()

    def write(self, **fields) -> dict:
        DECISIONS.labels(decision=str(fields.get("status", "unknown"))).inc()
        for attempt in range(3):
            try:
                with self._lock, self.db.begin() as c:
                    last = c.execute(text("SELECT seq, entry FROM audit_log ORDER BY seq DESC LIMIT 1")).first()
                    seq, prev = (last[0] + 1, json.loads(last[1])["hash"]) if last else (0, self.GENESIS)
                    body = {"seq": seq, "ts": time.time(), "prev": prev, **fields}
                    entry = {**body, "hash": self._digest(json.loads(_canon(body)), self.keys[0] if self.keys else None)}
                    c.execute(text("INSERT INTO audit_log (seq, entry) VALUES (:s, :e)"), {"s": seq, "e": json.dumps(entry, default=str)})
                    return entry
            except IntegrityError:  # another replica appended first; chain onto its entry
                if attempt == 2:
                    raise
        raise AssertionError("unreachable")

    def tail(self, limit: int = 100) -> list[dict]:
        with self.db.connect() as c:
            rows = c.execute(text("SELECT entry FROM audit_log ORDER BY seq DESC LIMIT :n"), {"n": limit}).all()
        return [json.loads(r[0]) for r in reversed(rows)]

    def verify(self) -> tuple[bool, str]:
        """ponytail: walks the whole chain; checkpoint signed heads once it grows past millions of rows."""
        prev, n = self.GENESIS, 0
        with self.db.connect() as c:
            for seq, raw in c.execute(text("SELECT seq, entry FROM audit_log ORDER BY seq")):
                e = json.loads(raw)
                body = {k: v for k, v in e.items() if k != "hash"}
                ok = any(hmac.compare_digest(self._digest(body, k), str(e.get("hash"))) for k in (self.keys or [None]))
                if seq != n or e.get("seq") != n or e.get("prev") != prev or not ok:
                    return False, f"entry {n} was altered, removed or reordered"
                prev, n = e["hash"], n + 1
        return True, f"{n} entries, chain intact"
