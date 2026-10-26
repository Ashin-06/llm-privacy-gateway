# Changelog

All notable changes to this project. Versions follow [semantic versioning](https://semver.org/).

## 1.0.0 — 2026-10-26

### Added
- `pyproject.toml` with a `privgate` console command, and pinned `requirements.lock` /
  `requirements-dev.lock` (generated with `uv pip compile --universal`).
- Container image: slim Python 3.12 base, non-root user, health check on `/healthz`.
- CI on every push: ruff, bandit, pip-audit, pytest with a coverage report.
- Settings from `PRIVGATE_*` environment variables, checked at startup. `PRIVGATE_ENV=production`
  refuses to start without hashed API keys, `PRIVGATE_VAULT_KEY`, `PRIVGATE_AUDIT_KEY`,
  `PRIVGATE_DATABASE_URL` and upstream credentials. No built-in secrets in any mode.
- Roles on API keys: `support`, `fraud_analyst` and `developer` use the gateway, `auditor` reads
  the audit trail, `monitor` scrapes metrics, `admin` does all three. Keys can be stored as
  `sha256:<hex>`; `python -m privgate.ops keygen` makes new ones.
- Per-client rate limit, request body cap, security headers, CORS only for listed origins.
- JSON logs with request IDs; `/healthz`, `/readyz` and Prometheus `/metrics`.
- Vault and audit trail in a database: SQLite by default, Postgres through
  `PRIVGATE_DATABASE_URL`, numbered SQL migrations (`python -m privgate migrate`).
- Key rotation: `PRIVGATE_VAULT_KEY_PREVIOUS` and `PRIVGATE_AUDIT_KEY_PREVIOUS` stay readable.
- `SECURITY.md`, `docs/threat-model.md`, `docs/runbook.md`.

### Changed
- The vault no longer lives in process memory, so placeholders survive restarts and work across
  replicas that share the database and vault key.
- The audit trail moved from `data/audit.jsonl` to the `audit_log` table; `PRIVGATE_AUDIT_LOG`
  is gone. The chain is now always HMAC-keyed.
- `/healthz` is a bare liveness check; the auth mode moved to `/readyz`.
- Validation errors no longer echo the submitted input, and upstream connection errors no
  longer pass the exception text to the caller.
- Without API keys the gateway refuses to listen on anything but loopback.

### Unchanged
- Detection, masking and restoration logic, and every benchmark and real-data number in the
  README.
