"""Settings, auth, limits, headers, metrics, health, persistence and migrations."""
import base64
import hashlib
import importlib
import json
import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from privgate import db, ops
from privgate.audit import Audit
from privgate.vault import Vault

K32 = base64.b64encode(b"v" * 32).decode()
A32 = base64.b64encode(b"a" * 32).decode()
KEY = "privgate_" + "x" * 40
HASHED = {f"sha256:{hashlib.sha256(KEY.encode()).hexdigest()}": {"user": "meera", "role": "support"}}


def prod_env(**over):
    env = {"PRIVGATE_ENV": "production", "PRIVGATE_API_KEYS": json.dumps(HASHED), "PRIVGATE_VAULT_KEY": K32,
           "PRIVGATE_AUDIT_KEY": A32, "PRIVGATE_DATABASE_URL": "sqlite://"}
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


def boot(monkeypatch, **env):
    for k in [k for k in os.environ if k.startswith("PRIVGATE_")]:
        monkeypatch.delenv(k)
    for k, v in env.items():
        monkeypatch.setenv(f"PRIVGATE_{k}", v)
    import privgate.gateway as gw

    return importlib.reload(gw)


def test_production_settings_accepted():
    s = ops.load_settings(prod_env())
    assert s.production and not s.demo and s.secret["VAULT_KEY"] == b"v" * 32 and not s.ephemeral


@pytest.mark.parametrize("change, message", [
    ({"PRIVGATE_API_KEYS": None}, "API keys"),
    ({"PRIVGATE_VAULT_KEY": None}, "VAULT_KEY"),
    ({"PRIVGATE_AUDIT_KEY": None}, "AUDIT_KEY"),
    ({"PRIVGATE_DATABASE_URL": None}, "DATABASE_URL"),
    ({"PRIVGATE_API_KEYS": json.dumps({KEY: {"user": "meera", "role": "support"}})}, "sha256"),
    ({"PRIVGATE_API_KEYS": json.dumps({"sha256:" + "0" * 64: {"user": "x", "role": "root"}})}, "roles"),
    ({"PRIVGATE_VAULT_KEY": base64.b64encode(b"short").decode()}, "32 bytes"),
    ({"PRIVGATE_VAULT_KEY": "not base64!"}, "base64"),
    ({"PRIVGATE_CORS_ORIGINS": "*"}, "CORS"),
    ({"PRIVGATE_ENV": "prod"}, "development or production"),
    ({"PRIVGATE_DATABASE_URL": "mysql://x"}, "postgresql"),
])
def test_production_refuses_to_start(change, message):
    with pytest.raises(ops.ConfigError, match=message):
        ops.load_settings(prod_env(**change))


def test_no_public_bind_without_keys():
    with pytest.raises(ops.ConfigError, match="without API keys"):
        ops.load_settings({"PRIVGATE_HOST": "0.0.0.0"})
    assert ops.load_settings({"PRIVGATE_HOST": "0.0.0.0", "PRIVGATE_API_KEYS": json.dumps(HASHED)}).host == "0.0.0.0"
    dev = ops.load_settings({})
    assert dev.demo and set(dev.ephemeral) == {"VAULT_KEY", "AUDIT_KEY"} and dev.database_url == "sqlite://"


def test_production_needs_upstream_credentials(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(ops.ConfigError, match="ANTHROPIC_API_KEY"):
        boot(monkeypatch, **{k.removeprefix("PRIVGATE_"): v for k, v in prod_env().items()})
    boot(monkeypatch)


def test_serve_exits_with_a_readable_error():
    env = {k: v for k, v in os.environ.items() if not k.startswith("PRIVGATE_")}
    r = subprocess.run([sys.executable, "-m", "privgate", "serve", "--host", "0.0.0.0"], env=env,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode != 0 and "without API keys" in r.stderr


def test_roles_decide_what_a_key_may_do(monkeypatch):
    keys = {"k-support": {"user": "meera", "role": "support"}, "k-audit": {"user": "asha", "role": "auditor"},
            "k-mon": {"user": "prom", "role": "monitor"}}
    gw = boot(monkeypatch, API_KEYS=json.dumps(keys))
    c = TestClient(gw.app)
    assert c.post("/v1/sanitize", json={"text": "hi"}).status_code == 401
    assert c.post("/v1/sanitize", json={"text": "hi"}, headers={"x-api-key": "wrong"}).status_code == 401
    assert c.post("/v1/sanitize", json={"text": "hi"}, headers={"x-api-key": "k-support"}).status_code == 200
    assert c.post("/v1/sanitize", json={"text": "hi"}, headers={"authorization": "Bearer k-audit"}).status_code == 403
    assert c.get("/v1/audit", headers={"x-api-key": "k-support"}).status_code == 403
    assert c.get("/v1/audit", headers={"x-api-key": "k-audit"}).status_code == 200
    assert c.get("/metrics", headers={"x-api-key": "k-support"}).status_code == 403
    m = c.get("/metrics", headers={"x-api-key": "k-mon"})
    assert m.status_code == 200 and 'http_requests_total{method="POST",route="/v1/sanitize",status="200"}' in m.text
    assert "http_request_duration_seconds_bucket" in m.text and "errors_total" in m.text


def test_rate_limit(monkeypatch):
    gw = boot(monkeypatch, RATE_LIMIT="3")
    c = TestClient(gw.app)
    codes = [c.post("/v1/sanitize", json={"text": "hi"}).status_code for _ in range(5)]
    assert codes[:3] == [200] * 3 and codes[3:] == [429, 429]
    r = c.post("/v1/sanitize", json={"text": "hi"})
    assert int(r.headers["retry-after"]) >= 1
    assert c.get("/healthz").status_code == 200  # probes are never limited


def test_body_size_cap(monkeypatch):
    gw = boot(monkeypatch, MAX_BODY_BYTES="1000")
    c = TestClient(gw.app)
    assert c.post("/v1/sanitize", json={"text": "a" * 2000}).status_code == 413

    def chunks():  # no content-length: the cap still holds
        for _ in range(20):
            yield b"a" * 100

    assert c.post("/v1/sanitize", content=chunks(), headers={"content-type": "application/json"}).status_code == 413
    assert c.post("/v1/sanitize", json={"text": "ok"}).status_code == 200


def test_headers_and_request_ids(monkeypatch):
    c = TestClient(boot(monkeypatch).app)
    r = c.post("/v1/sanitize", json={"text": "hi"}, headers={"x-request-id": "abc-123"})
    assert r.headers["x-request-id"] == "abc-123"
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert r.headers["content-security-policy"] == ops.API_CSP and r.headers["cache-control"] == "no-store"
    assert "unsafe-inline" in c.get("/").headers["content-security-policy"]
    assert len(c.get("/healthz", headers={"x-request-id": "bad id\n"}).headers["x-request-id"]) == 32
    assert "access-control-allow-origin" not in c.get("/healthz", headers={"origin": "https://evil.example"}).headers


def test_cors_only_for_listed_origins(monkeypatch):
    c = TestClient(boot(monkeypatch, CORS_ORIGINS="https://console.bank.example").app)
    ok = c.get("/healthz", headers={"origin": "https://console.bank.example"})
    assert ok.headers["access-control-allow-origin"] == "https://console.bank.example"
    assert "access-control-allow-origin" not in c.get("/healthz", headers={"origin": "https://evil.example"}).headers


def test_errors_do_not_leak(monkeypatch):
    gw = boot(monkeypatch)

    @gw.app.get("/boom")
    def boom():
        raise RuntimeError("secret detail: card 4111111111111111")

    c = TestClient(gw.app)
    r = c.get("/boom")
    assert r.status_code == 500 and "4111" not in r.text and r.json()["request_id"] == r.headers["x-request-id"]
    bad = c.post("/v1/sanitize", json={"text": ["4111111111111111"], "conversation": "c"})
    assert bad.status_code == 422 and "4111" not in bad.text
    assert c.post("/v1/messages", content=b"{not json", headers={"content-type": "application/json"}).status_code == 400


def test_health_and_readiness(monkeypatch):
    gw = boot(monkeypatch)
    c = TestClient(gw.app)
    assert c.get("/healthz").json() == {"status": "ok"}
    r = c.get("/readyz")
    assert r.status_code == 200 and r.json()["checks"] == {"database": True, "policy": True}
    gw.store.dispose()
    monkeypatch.setattr(gw.store, "connect", lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    r = c.get("/readyz")
    assert r.status_code == 503 and r.json()["checks"]["database"] is False and "db down" not in r.text


def test_json_logs_carry_request_ids(capsys):
    ops.setup_logging("INFO")
    token = ops.request_id.set("rid-1")
    ops.log.info("hello", extra={"fields": {"n": 1}})
    ops.request_id.reset(token)
    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["msg"] == "hello" and line["request_id"] == "rid-1" and line["n"] == 1 and line["level"] == "INFO"


def _url(tmp_path):
    return os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{tmp_path / 'state.db'}"


def test_vault_and_audit_survive_a_restart(tmp_path):
    url = _url(tmp_path)
    key = b"k" * 32
    v = Vault(key=key, engine=db.connect(url))
    v.forget("conv-r")
    ph = v.tokenize("conv-r", "PAN", "ABCPS1234K")
    assert v.claim("conv-r", "meera")
    a = Audit(db.connect(url), key=key)
    n = len(a.tail(10_000))
    a.write(user="meera", status="ok")

    v2 = Vault(key=key, engine=db.connect(url))  # a new process, same database and key
    assert v2.reveal("conv-r", ph) == "ABCPS1234K"
    assert v2.tokenize("conv-r", "PAN", "abcps 1234k") == ph  # the same value keeps its placeholder
    assert not v2.claim("conv-r", "ravi") and v2.owner("conv-r") == "meera"
    a2 = Audit(db.connect(url), key=key)
    assert len(a2.tail(10_000)) == n + 1 and a2.verify()[0]

    rotated = Vault(key=b"n" * 32, engine=db.connect(url), previous_keys=(key,))
    assert rotated.reveal("conv-r", ph) == "ABCPS1234K"  # old entries stay readable while rotating
    assert Vault(key=b"n" * 32, engine=db.connect(url)).reveal("conv-r", ph) is None
    assert Audit(db.connect(url), key=b"n" * 32, previous_keys=(key,)).verify()[0]
    v2.forget("conv-r")


def test_expired_conversations_are_dropped(tmp_path):
    v = Vault(ttl_seconds=-1, engine=db.connect(f"sqlite:///{tmp_path / 'ttl.db'}"))
    ph = v.tokenize("old", "PAN", "ABCPS1234K")
    v.tokenize("new", "PAN", "ABCPS1234K")  # any write sweeps out expired conversations
    assert v.reveal("old", ph) is None


def test_migrations_apply_once(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    eng = db.engine(url)
    assert db.migrate(eng) == ["001_init.sql"]
    assert db.migrate(eng) == []
    with eng.connect() as c:
        assert [r[0] for r in c.execute(text("SELECT version FROM schema_migrations"))] == [1]
        tables = {r[0] for r in c.execute(text("SELECT name FROM sqlite_master WHERE type = 'table'"))}
    assert {"conversations", "vault_entries", "audit_log"} <= tables
    env = {**{k: v for k, v in os.environ.items() if not k.startswith("PRIVGATE_")}, "PRIVGATE_DATABASE_URL": url}
    out = subprocess.run([sys.executable, "-m", "privgate", "migrate"], env=env, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0 and "up to date" in out.stdout
