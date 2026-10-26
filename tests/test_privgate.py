import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from privgate import db

from privgate.audit import Audit
from privgate.bench import run
from privgate.checksums import gstin_check_char, luhn_digit, luhn_valid, verhoeff_digit, verhoeff_valid
from privgate.detect import detect
from privgate.engine import Blocked, Engine
from privgate.vault import Vault

AADHAAR = "23456789012" + verhoeff_digit("23456789012")
CARD = "411111111111111" + luhn_digit("411111111111111")


def test_checksums():
    assert verhoeff_valid(AADHAAR) and not verhoeff_valid(AADHAAR[:-1] + str((int(AADHAAR[-1]) + 1) % 10))
    assert luhn_valid("4111111111111111") and not luhn_valid("4111111111111112")
    assert gstin_check_char("27AAPFU0939F1Z") == "V"  # published sample GSTIN 27AAPFU0939F1ZV


def test_validation_rejects_lookalikes():
    kinds = {e.type for e in detect("Order 123456789012, tracking 4111111111111112, call 1800 425 3800")}
    assert "AADHAAR" not in kinds and "CARD" not in kinds


def test_masking_is_stable_and_reversible():
    eng = Engine()
    text = f"PAN ABCPS1234K and again ABCPS1234K; Aadhaar {AADHAAR}; Customer name: Priya Sharma"
    r = eng.sanitize(text, "c1")
    assert "ABCPS1234K" not in r.text and AADHAAR not in r.text and "Priya" not in r.text
    assert r.text.count("[[PAN_1]]") == 2
    back, _ = eng.restore(r.text, "c1", "fraud_analyst")
    assert back == text
    partial, stats = eng.restore(r.text, "c1", "support")
    assert "[[PAN_1]]" in partial and "Priya Sharma" in partial and stats["PAN:kept_masked"] == 2


def test_blocked_data_refuses_request():
    with pytest.raises(Blocked):
        Engine().sanitize(f"card {CARD} cvv 123", "c2")
    with pytest.raises(Blocked):
        Engine().sanitize("deploy with AKIAIOSFODNN7EXAMPLE", "c3")


def test_vault_encrypts_and_scopes_by_conversation():
    v = Vault()
    ph = v.tokenize("a", "PAN", "ABCPS1234K")
    with v.db.connect() as c:
        stored = " ".join(str(x) for row in c.execute(text("SELECT * FROM vault_entries")) for x in row)
    assert "abcps1234k" not in stored.lower()
    assert v.reveal("a", ph) == "ABCPS1234K" and v.reveal("b", ph) is None


def test_audit_tamper_detection(tmp_path):
    store = db.connect(f"sqlite:///{tmp_path / 'a.db'}")
    a = Audit(store, key=b"k" * 32)
    for i in range(3):
        a.write(user="u", n=i)
    assert a.verify()[0]
    with store.begin() as c:
        e = json.loads(c.execute(text("SELECT entry FROM audit_log WHERE seq = 1")).scalar())
        c.execute(text("UPDATE audit_log SET entry = :e WHERE seq = 1"), {"e": json.dumps({**e, "user": "someone-else"})})
    assert not Audit(store, key=b"k" * 32).verify()[0]
    with store.begin() as c:
        c.execute(text("UPDATE audit_log SET entry = :e WHERE seq = 1"), {"e": json.dumps(e)})
        c.execute(text("DELETE FROM audit_log WHERE seq = 1"))
    assert not Audit(store, key=b"k" * 32).verify()[0]  # a gap in the chain
    assert not Audit(store, key=b"x" * 32).verify()[0]  # the wrong key


def test_benchmark_beats_naive_regex():
    r = run(200, seed=3)
    for t in ("AADHAAR", "CARD", "ACCOUNT"):
        assert r["gateway"][t]["f1"] > r["naive_regex"][t]["f1"] + 0.3


class _FakeMessages:
    def __init__(self):
        self.last = None

    def create(self, **kw):
        self.last = kw
        text = kw["messages"][0]["content"]
        reply = "Dear [[PERSON_1]], we refunded your card [[CARD_1:1111]]. Also your other PAN is BQZPK7781M."
        assert "Priya" not in text and "4111" not in text  # nothing sensitive went upstream
        return SimpleNamespace(model_dump=lambda: {"id": "msg_1", "type": "message", "role": "assistant", "model": kw["model"],
                                                   "content": [{"type": "text", "text": reply}], "stop_reason": "end_turn"})


def test_proxy_end_to_end(tmp_path, monkeypatch):
    import importlib

    import privgate.gateway as gw

    importlib.reload(gw)
    fake = _FakeMessages()
    gw.set_upstream(SimpleNamespace(messages=fake, beta=SimpleNamespace(messages=fake)))
    c = TestClient(gw.app)
    body = {"model": "claude-opus-5-5", "max_tokens": 500,
            "messages": [{"role": "user", "content": f"Customer name: Priya Sharma, card {CARD}. Draft a refund note."}]}
    r = c.post("/v1/messages", json=body, headers={"x-privgate-user": "agent7", "x-privgate-role": "support"})
    assert r.status_code == 200
    reply = r.json()["content"][0]["text"]
    assert "Priya Sharma" in reply  # support may see names
    assert "[[CARD_1:1111]]" in reply  # but not card numbers
    assert "BQZPK7781M" not in reply  # PII the model invented is masked on the way back
    entry = c.get("/v1/audit").json()["entries"][-1]
    assert entry["leaks_in_reply"] == {"PAN": 1} and entry["masked"]["CARD:tokenize"] == 1
    bad = c.post("/v1/messages", json={**body, "model": "some-other-model"})
    assert bad.status_code == 403
    blocked = c.post("/v1/messages", json={**body, "messages": [{"role": "user", "content": "otp is 482913"}]})
    assert blocked.status_code == 422


def test_gateway_keys_decide_identity(tmp_path, monkeypatch):
    keys = {"k-support": {"user": "meera", "role": "support"}, "k-fraud": {"user": "ravi", "role": "fraud_analyst"}}
    monkeypatch.setenv("PRIVGATE_API_KEYS", json.dumps(keys))
    import importlib

    import privgate.gateway as gw

    importlib.reload(gw)
    fake = _FakeMessages()
    gw.set_upstream(SimpleNamespace(messages=fake, beta=SimpleNamespace(messages=fake)))
    c = TestClient(gw.app)
    body = {"model": "claude-opus-5-5", "max_tokens": 500,
            "messages": [{"role": "user", "content": f"Customer name: Priya Sharma, card {CARD}. Draft a refund note."}]}
    assert c.post("/v1/messages", json=body).status_code == 401
    # a support key claiming to be a fraud analyst still gets support visibility
    r = c.post("/v1/messages", json=body, headers={"x-api-key": "k-support", "x-privgate-role": "fraud_analyst"})
    assert r.status_code == 200 and "[[CARD_1:1111]]" in r.json()["content"][0]["text"]
    cid = r.headers["x-privgate-conversation"]
    # another user cannot reuse or restore the conversation, even with a broader role
    assert c.post("/v1/messages", json=body, headers={"x-api-key": "k-fraud", "x-privgate-conversation": cid}).status_code == 403
    out = c.post("/v1/restore", json={"text": "[[PERSON_1]]", "conversation": cid}, headers={"x-api-key": "k-fraud"}).json()
    assert out["text"] == "[[PERSON_1]]" and out["stats"]["not_conversation_owner"] == 1
    assert c.get("/v1/audit").status_code == 401
    assert c.get("/readyz").json()["auth"] == "api keys"
    monkeypatch.delenv("PRIVGATE_API_KEYS")
    importlib.reload(gw)
