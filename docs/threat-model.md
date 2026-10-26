# Threat model

What the gateway protects, from whom, and what is still open. Written for the 1.0.0 code; it has
not been reviewed by anyone independent.

## What it protects

| Asset | Where it lives |
|---|---|
| Customer identifiers in prompts (Aadhaar, PAN, card and account numbers, names, contacts) | in transit through the gateway; sealed in the vault |
| Vault entries (original values behind placeholders) | `vault_entries` table, AES-256-GCM, conversation ID as associated data |
| Vault key, audit key | environment / secret store (`PRIVGATE_VAULT_KEY`, `PRIVGATE_AUDIT_KEY`) |
| Gateway API keys | callers hold the key; the gateway holds only SHA-256 hashes |
| Upstream model credentials | `ANTHROPIC_API_KEY` on the gateway host only |
| Audit trail | `audit_log` table, HMAC chain |

## Trust boundaries

```
employee / app ──(TLS at your ingress)──► gateway ──(TLS)──► model provider
                                            │
                                            └──► database (vault, audit)
```

1. **Caller → gateway.** Callers are authenticated by API key; the key, not any header, decides
   user and role.
2. **Gateway → model provider.** Everything crossing this line is treated as disclosed to a third
   party. Only sanitised text should cross it.
3. **Gateway → database.** The database holds ciphertext, HMAC lookups, owners, timestamps and
   audit counts. A database dump without the vault key reveals no masked value.

## Threats and what stops them

| Threat | Mitigation | Residual risk |
|---|---|---|
| An identifier reaches the provider unmasked | Checksum- and label-based detection; block list for CVV/OTP/secrets; images and documents refused | **Detection misses things.** On realistic documents 37.5% of targeted identifiers were masked; names in free prose are mostly missed (see README). Treat the gateway as one control, not a guarantee. |
| An employee sees values their role shouldn't | Restoration per role from `policy.toml`; role comes from the key | A role's reveal list is only as narrow as the policy you write |
| One user reads another user's conversation | Conversations are bound to their first user; restore returns nothing to anyone else | Conversation IDs are bearer-like within a user; don't log them in shared places |
| Model invents or completes an identifier | Reply is scanned; leaks masked and counted as `leaks_in_reply` | Same detector limits as above |
| Stolen API key | Keys are per client and revocable; rate limit per key; audit records user and role | A stolen key works until removed from the key list and the service restarts |
| Brute-forcing keys | 256-bit random keys; rate limit per address for unknown keys | Rate limit is per process (see below) |
| Database stolen | Values sealed with AES-256-GCM; lookups are keyed HMACs | Who talked to the gateway, when and how often is visible |
| Vault key stolen with the database | — | Every sealed value inside the TTL is readable. Keep the key in a KMS/HSM-backed secret store. |
| Audit trail edited | HMAC chain; any edit, deletion in the middle or reordering fails `/v1/audit` verification | Truncating the newest entries is only caught if you keep the chain head elsewhere (export it periodically) |
| Oversized or flooding requests | Body cap (2 MB default), prompt-size limit, per-client token bucket | Per process; several replicas multiply the limit — put a shared limiter at the ingress |
| Error messages leak data | Validation errors carry no input; unhandled errors return only a request ID; upstream auth failures become a generic 502 | Upstream 4xx messages other than 401/403 are passed through so callers can fix requests |
| Browser attacks on the playground | Security headers, CSP, `frame-ancestors 'none'`, no CORS unless origins are listed | The playground's CSP allows its own inline script; don't serve it on a shared origin |
| Misconfigured production start | `PRIVGATE_ENV=production` refuses to start without keys, secrets, database and upstream credentials; no public bind without keys | Production mode can't check that the keys are *good*, only that they exist and have the right shape |

## Not covered

- TLS. Terminate it at your ingress or service mesh; the gateway speaks plain HTTP.
- Streaming responses (refused).
- Data in images and PDFs (refused by default).
- The model provider's own handling of sanitised prompts.
- Insider with database *and* key access.
