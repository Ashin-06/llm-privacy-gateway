"""Messages-API-compatible privacy gateway.

Point any Anthropic SDK client at it (`base_url="http://gateway:8010"`). Every text
block in the system prompt, messages and tool results is sanitised before the request
goes upstream; placeholders in the reply are restored for the caller's role; anything
sensitive the model produced on its own is caught; and the whole exchange is audited.

    uvicorn privgate.gateway:app --port 8010

Headers:  x-privgate-user, x-privgate-role, x-privgate-conversation (reuse to keep
          placeholders stable across turns; a new id is returned when absent)
"""
from __future__ import annotations

import copy
import os
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from .audit import Audit
from .engine import Blocked, Engine

ROOT = Path(__file__).resolve().parent.parent
engine = Engine(os.environ.get("PRIVGATE_POLICY", ROOT / "policy.toml"))
audit = Audit(os.environ.get("PRIVGATE_AUDIT_LOG", ROOT / "data" / "audit.jsonl"))
app = FastAPI(title="LLM Privacy Gateway", version="1.0")
_upstream = None


def upstream():
    """The real Anthropic client (created lazily so the gateway starts without a key)."""
    global _upstream
    if _upstream is None:
        import anthropic

        _upstream = anthropic.Anthropic(base_url=os.environ.get("PRIVGATE_UPSTREAM_URL") or None)
    return _upstream


def set_upstream(client) -> None:
    global _upstream
    _upstream = client


def _walk_text(body: dict, fn) -> None:
    """Apply fn to every text field the model will read."""
    sys = body.get("system")
    if isinstance(sys, str):
        body["system"] = fn(sys)
    elif isinstance(sys, list):
        for b in sys:
            if b.get("type") == "text":
                b["text"] = fn(b["text"])
    for msg in body.get("messages", []):
        if isinstance(msg.get("content"), str):
            msg["content"] = fn(msg["content"])
            continue
        for b in msg.get("content", []):
            t = b.get("type")
            if t == "text":
                b["text"] = fn(b["text"])
            elif t == "tool_result":
                if isinstance(b.get("content"), str):
                    b["content"] = fn(b["content"])
                else:
                    for inner in b.get("content", []):
                        if inner.get("type") == "text":
                            inner["text"] = fn(inner["text"])
            elif t == "tool_use":
                b["input"] = _walk_json(b.get("input", {}), fn)
            elif t in ("image", "document") and not engine.policy.get("limits", {}).get("allow_binary", False):
                raise HTTPException(422, f"{t} blocks cannot be scanned for personal data; blocked by policy")


def _walk_json(obj, fn):
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        return [_walk_json(v, fn) for v in obj]
    if isinstance(obj, dict):
        return {k: _walk_json(v, fn) for k, v in obj.items()}
    return obj


@app.post("/v1/messages")
async def messages(request: Request, x_privgate_user: str = Header("anonymous"), x_privgate_role: str = Header("developer"),
                   x_privgate_conversation: str | None = Header(None)):
    t0 = time.time()
    body = await request.json()
    cid = x_privgate_conversation or uuid.uuid4().hex
    model = body.get("model", "")
    allowed_models = {m for d in engine.policy.get("destinations", {}).values() for m in d.get("models", [])}
    if allowed_models and model not in allowed_models:
        audit.write(user=x_privgate_user, role=x_privgate_role, conversation=cid, model=model, status="rejected", reason="model not approved")
        raise HTTPException(403, f"model {model!r} is not an approved destination")
    if body.get("stream"):
        raise HTTPException(400, "streaming is not supported through the gateway; send stream=false")
    if len(str(body)) > engine.policy.get("limits", {}).get("max_prompt_chars", 10**9):
        raise HTTPException(413, "prompt too large")

    totals: dict = {}
    clean = copy.deepcopy(body)

    def sanitize(text: str) -> str:
        r = engine.sanitize(text, cid)
        for k, v in r.actions.items():
            totals[k] = totals.get(k, 0) + v
        return r.text

    try:
        _walk_text(clean, sanitize)
    except Blocked as e:
        audit.write(user=x_privgate_user, role=x_privgate_role, conversation=cid, model=model, status="blocked", kinds=sorted(set(e.kinds)))
        raise HTTPException(422, str(e)) from e

    import anthropic

    params = {k: v for k, v in clean.items() if k != "betas"}
    try:
        client = upstream()
        resp = client.beta.messages.create(betas=clean["betas"], **params) if clean.get("betas") else client.messages.create(**params)
    except anthropic.APIStatusError as e:
        audit.write(user=x_privgate_user, role=x_privgate_role, conversation=cid, model=model, status="upstream_error", code=e.status_code)
        return JSONResponse(status_code=e.status_code, content={"type": "error", "error": {"type": "upstream_error", "message": e.message}})
    except (anthropic.APIConnectionError, TypeError) as e:  # TypeError: no credentials configured
        audit.write(user=x_privgate_user, role=x_privgate_role, conversation=cid, model=model, status="upstream_unavailable")
        raise HTTPException(502, f"upstream unavailable: {e}") from e

    out = resp.model_dump() if hasattr(resp, "model_dump") else dict(resp)
    restored, leaks = {}, {}
    mask_leaks = engine.policy.get("limits", {}).get("mask_leaks", True)
    for block in out.get("content", []):
        if block.get("type") != "text":
            continue
        for e in engine.leaked(block["text"]):
            leaks[e.type] = leaks.get(e.type, 0) + 1
        if leaks and mask_leaks:
            block["text"] = engine.sanitize(block["text"], cid, raise_on_block=False).text
        block["text"], stats = engine.restore(block["text"], cid, x_privgate_role)
        for k, v in stats.items():
            restored[k] = restored.get(k, 0) + v
    audit.write(user=x_privgate_user, role=x_privgate_role, conversation=cid, model=model, status="ok",
                masked=totals, restored=restored, leaks_in_reply=leaks, stop_reason=out.get("stop_reason"),
                latency_ms=round((time.time() - t0) * 1000))
    return JSONResponse(out, headers={"x-privgate-conversation": cid})


class TextIn(BaseModel):
    text: str = Field(..., max_length=400_000)
    conversation: str | None = None
    role: str | None = None


@app.post("/v1/sanitize")
def sanitize_preview(body: TextIn):
    cid = body.conversation or uuid.uuid4().hex
    r = engine.sanitize(body.text, cid, raise_on_block=False)
    blocked = sorted({e.type for e in r.entities if engine.action(e.type) == "block"})
    return {"conversation": cid, "sanitized": r.text, "blocked": blocked,
            "entities": [{"type": e.type, "start": e.start, "end": e.end, "confidence": e.confidence, "note": e.note,
                          "action": engine.action(e.type)} for e in r.entities]}


@app.post("/v1/restore")
def restore(body: TextIn):
    if not body.conversation:
        raise HTTPException(400, "conversation is required")
    text, stats = engine.restore(body.text, body.conversation, body.role)
    return {"text": text, "stats": stats}


@app.get("/v1/audit")
def audit_log(limit: int = 100):
    ok, msg = audit.verify()
    return {"verified": ok, "message": msg, "entries": audit.entries[-min(limit, 1000):]}


@app.get("/")
def playground():
    return FileResponse(ROOT / "web" / "index.html")
