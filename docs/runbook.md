# Runbook

How to deploy, configure and operate the gateway. Commands assume the repository root.

## Deploy

```bash
docker build -t llm-privacy-gateway:1.0.0 .
python -m privgate.ops keygen          # one API key per client, plus the vault and audit keys
docker run -d --name privgate -p 8010:8010 -v privgate-data:/data \
  -e PRIVGATE_KEYS_FILE=/run/secrets/privgate-keys.json \
  -e PRIVGATE_VAULT_KEY=... -e PRIVGATE_AUDIT_KEY=... -e ANTHROPIC_API_KEY=... \
  llm-privacy-gateway:1.0.0
curl -fsS http://127.0.0.1:8010/readyz
```

The image runs in production mode as a non-root user and keeps its SQLite database in the `/data`
volume. It refuses to start, and logs why, when anything required is missing. Terminate TLS in
front of it.

For more than one replica, use Postgres (`PRIVGATE_DATABASE_URL=postgresql://user:pass@host/db`),
give every replica the same vault and audit keys, and put a shared rate limiter at the ingress.

Without Docker: `pip install -r requirements.lock && pip install -e .`, then `privgate serve`.

## Configure

| Variable | Required in production | Meaning |
|---|---|---|
| `PRIVGATE_ENV` | — | `development` (default) or `production` |
| `PRIVGATE_API_KEYS` / `PRIVGATE_KEYS_FILE` | yes | JSON `{"sha256:<hex>": {"user": "...", "role": "..."}}`. Roles: `support`, `fraud_analyst`, `developer` (use the gateway), `auditor` (`/v1/audit`), `monitor` (`/metrics`), `admin` |
| `PRIVGATE_VAULT_KEY` | yes | base64, exactly 32 bytes |
| `PRIVGATE_AUDIT_KEY` | yes | base64, at least 32 bytes |
| `PRIVGATE_DATABASE_URL` | yes | `sqlite:////data/privgate.db` or `postgresql://...` (default in development: in memory) |
| `ANTHROPIC_API_KEY` or `PRIVGATE_UPSTREAM_URL` | yes | upstream credentials or an internal proxy |
| `PRIVGATE_HOST`, `PRIVGATE_PORT` | — | default `127.0.0.1:8010`; any non-loopback address needs API keys |
| `PRIVGATE_RATE_LIMIT` | — | requests per minute per client (default 120) |
| `PRIVGATE_MAX_BODY_BYTES` | — | default 2,000,000 |
| `PRIVGATE_CORS_ORIGINS` | — | comma-separated origins allowed to call from a browser; none by default |
| `PRIVGATE_POLICY` | — | policy file (default `policy.toml`) |
| `PRIVGATE_LOG_LEVEL` | — | default `INFO` |
| `FORWARDED_ALLOW_IPS` | — | addresses of proxies whose `X-Forwarded-For` is trusted (uvicorn) |

## Watch

- `GET /healthz`: the process is up (used by the container health check).
- `GET /readyz`: database reachable and policy loaded; 503 otherwise.
- `GET /metrics` (role `monitor`): `http_requests_total`, `http_request_duration_seconds`,
  `errors_total`, `privgate_decisions_total{decision="ok|blocked|rejected|upstream_error|upstream_unavailable"}`.
- Logs are one JSON object per line on stdout, each with a `request_id` that is also returned in
  the `X-Request-ID` response header.

Suggested alerts: `/readyz` failing for 2 minutes; `errors_total{kind="unhandled"}` increasing;
5xx share above 1% for 10 minutes; a sudden rise in `decision="blocked"` or in `leaks_in_reply`;
`/v1/audit` returning `verified: false`.

## Rotate keys

**API keys.** Add the new hash to the key file, restart, give the client the new key, then remove
the old hash and restart again.

**Vault key.** Set `PRIVGATE_VAULT_KEY_PREVIOUS` to the current key and `PRIVGATE_VAULT_KEY` to a
new one, then restart. New values are sealed with the new key; older ones stay readable. After the
conversation TTL (one hour) nothing needs the old key: remove `_PREVIOUS` and restart.

**Audit key.** Same pattern with `PRIVGATE_AUDIT_KEY_PREVIOUS`. Keep old audit keys for as long as
you keep the entries they signed, or verification of those entries fails.

**Upstream key.** Replace `ANTHROPIC_API_KEY` and restart.

## Back up and restore

SQLite (in the `/data` volume):

```bash
docker exec privgate python -c "import sqlite3; s=sqlite3.connect('/data/privgate.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d)"
docker cp privgate:/data/backup.db ./privgate-$(date +%F).db
```

Restore: stop the container, copy the backup to `/data/privgate.db` in the volume, start it, check
`/readyz` and `GET /v1/audit` (`verified: true`).

Postgres: `pg_dump` / `pg_restore` as usual. Migrations are applied automatically on start, or with
`python -m privgate migrate`.

Backups contain sealed values: store them like the database itself, and keep the keys that were in
use (including `_PREVIOUS`) with a separate custodian.

## Incidents

1. **Leaked API key.** Remove its hash from the key file and restart. Search the logs and
   `/v1/audit` for that user. Issue a new key.
2. **Leaked vault key.** Treat every value sealed in the last TTL window as exposed. Rotate the key
   without `_PREVIOUS` (old conversations become unreadable), restart, and follow the bank's
   data-breach procedure (DPDP Act notification duties).
3. **Identifier reached the provider.** Find the request by `request_id` in the logs and its audit
   entry. Add a pattern or policy rule that would have caught it, add a test, redeploy. Follow the
   provider's data deletion process.
4. **Audit verification fails.** Stop writes if you can, take a copy of the database, and compare
   with the latest backup to find the first broken entry. Treat it as possible tampering.
5. **Upstream outage.** Requests return 502 and `decision="upstream_unavailable"` rises. Nothing is
   queued; callers retry.
