"""Hash-chained audit log. Entries hold counts and decisions, never the sensitive values."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


class Audit:
    GENESIS = "0" * 64

    def __init__(self, path: str | Path | None = None, key: bytes | None = None):
        self.path = Path(path) if path else None
        self.key = key if key is not None else (os.environ.get("PRIVGATE_AUDIT_KEY", "").encode() or None)
        self.entries: list[dict] = []
        self._lock = threading.Lock()
        if self.path and self.path.exists():
            self.entries = [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]

    def _digest(self, body: dict) -> str:
        data = _canon(body)
        return hmac.new(self.key, data, hashlib.sha256).hexdigest() if self.key else hashlib.sha256(data).hexdigest()

    def write(self, **fields) -> dict:
        with self._lock:
            body = {"seq": len(self.entries), "ts": time.time(), "prev": self.entries[-1]["hash"] if self.entries else self.GENESIS, **fields}
            entry = {**body, "hash": self._digest(body)}
            self.entries.append(entry)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
            return entry

    def verify(self) -> tuple[bool, str]:
        prev = self.GENESIS
        for i, e in enumerate(self.entries):
            body = {k: v for k, v in e.items() if k != "hash"}
            if e.get("seq") != i or e.get("prev") != prev or not hmac.compare_digest(self._digest(json.loads(_canon(body))), e["hash"]):
                return False, f"entry {i} was altered, removed or reordered"
            prev = e["hash"]
        return True, f"{len(self.entries)} entries, chain intact"
