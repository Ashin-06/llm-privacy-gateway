"""Policy-driven sanitisation and restoration of text."""
from __future__ import annotations

import re
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .detect import Entity, detect
from .vault import PLACEHOLDER, Vault

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "policy.toml"


class Blocked(Exception):
    def __init__(self, kinds: list[str]):
        super().__init__("request contains data that must never leave the bank: " + ", ".join(sorted(set(kinds))))
        self.kinds = kinds


@dataclass
class Result:
    text: str
    entities: list[Entity] = field(default_factory=list)
    actions: Counter = field(default_factory=Counter)


class Engine:
    def __init__(self, policy_path: str | Path = DEFAULT_POLICY, vault: Vault | None = None):
        with open(policy_path, "rb") as f:
            self.policy = tomllib.load(f)
        self.vault = vault or Vault()
        self.custom = {k: re.compile(v) for k, v in self.policy.get("custom_patterns", {}).items()}

    def action(self, kind: str) -> str:
        return self.policy["actions"].get(kind, "tokenize")

    def scan(self, text: str) -> list[Entity]:
        floor = self.policy.get("limits", {}).get("min_confidence", 0.0)
        return [e for e in detect(text, self.custom) if e.confidence >= floor]

    def sanitize(self, text: str, cid: str, raise_on_block: bool = True) -> Result:
        ents = self.scan(text)
        blocked = [e.type for e in ents if self.action(e.type) == "block"]
        if blocked and raise_on_block:
            raise Blocked(blocked)
        out, last, acts = [], 0, Counter()
        for e in ents:
            act = self.action(e.type)
            out.append(text[last : e.start])
            if act == "allow":
                out.append(text[e.start : e.end])
            elif act in ("redact", "block"):
                out.append(f"[REDACTED:{e.type}]")
            else:
                hint = ""
                if self.policy.get("hints", {}).get(e.type) == "last4":
                    hint = re.sub(r"\D", "", e.value)[-4:]
                out.append(self.vault.tokenize(cid, e.type, e.value, hint))
            acts[f"{e.type}:{act}"] += 1
            last = e.end
        out.append(text[last:])
        return Result("".join(out), ents, acts)

    def restore(self, text: str, cid: str, role: str | None, user: str | None = None) -> tuple[str, Counter]:
        """Put original values back for the kinds `role` may see. When `user` is given,
        only the conversation's owner gets anything back."""
        allowed = set(self.policy.get("roles", {}).get(role or "", {}).get("reveal", []))
        stats = Counter()
        owner = self.vault.owner(cid)
        if user is not None and owner is not None and owner != user:
            allowed = set()
            stats["not_conversation_owner"] += 1

        def swap(m: re.Match) -> str:
            kind = m.group(1)
            if kind not in allowed:
                stats[f"{kind}:kept_masked"] += 1
                return m.group(0)
            val = self.vault.reveal(cid, m.group(0))
            stats[f"{kind}:{'revealed' if val else 'unknown'}"] += 1
            return val if val is not None else m.group(0)

        return PLACEHOLDER.sub(swap, text), stats

    def leaked(self, text: str) -> list[Entity]:
        """Sensitive data in a model *reply* that did not come from a placeholder (the
        model guessed, completed or hallucinated an identifier)."""
        return [e for e in self.scan(text) if self.action(e.type) != "allow"]
