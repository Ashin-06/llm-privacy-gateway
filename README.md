# LLM Privacy Gateway

A proxy that sits between bank staff and an external LLM. Before a prompt leaves the bank it masks or blocks customer identifiers such as Aadhaar, PAN, card and account numbers. When the reply comes back it restores the real values only for roles that are allowed to see them, and every exchange is written to a tamper-evident audit log.

The gateway speaks the Anthropic Messages API, so existing client code only needs a new `base_url`.

```
employee / app ──► gateway ──(masked prompt)──► LLM provider
                     │  ▲
                     │  └── values restored per role, leaks in the reply masked
                     └── encrypted vault · policy · audit log
```

## Features

- Detects Indian banking identifiers and confirms them with their check digits (Verhoeff for Aadhaar, Luhn for cards, mod-36 for GSTIN), so order numbers and UTRs are not mistaken for them.
- Per-type policy: replace with a reversible placeholder, redact, block the request, or allow.
- Placeholders such as `[[PAN_1]]` stay the same within a conversation, so the model can still reason about them.
- Original values are kept in an AES-256-GCM vault in SQLite or Postgres, tied to the conversation and the user who started it.
- Identifiers that the model invents in its reply are masked before the employee sees them.
- Per-client API keys with roles, rate limits, JSON logs, Prometheus metrics and an HMAC-chained audit log.
- A browser playground that shows each step on a sample ticket without calling a model.

## Quick start

```bash
pip install -r requirements.txt
python -m pytest -q                     # 38 tests
python -m privgate serve                # gateway and playground on http://127.0.0.1:8010
python -m privgate scan ticket.txt      # show what would be detected
python -m privgate mask ticket.txt      # print the masked text
```

Without API keys the gateway runs in demo mode and only listens on localhost. For production settings, see [docs/runbook.md](docs/runbook.md).

## Using it from code

```python
import anthropic

client = anthropic.Anthropic(
    base_url="http://127.0.0.1:8010",
    api_key="<gateway key for this employee or app>",
)
reply = client.messages.create(
    model="<an approved model id from policy.toml>",
    max_tokens=2000,
    messages=[{"role": "user", "content": ticket_text}],
)
```

Send back the `x-privgate-conversation` header from the first response to keep placeholders stable across turns. The gateway calls the provider with its own credentials, so employees never hold the provider key.

## What gets detected

| Type | How it is confirmed |
|---|---|
| Aadhaar | 12 digits with a valid Verhoeff check digit |
| Card | 13–19 digits, Luhn check and a known network prefix |
| PAN | `AAAAA9999A` with a valid holder-type letter |
| GSTIN | state code, PAN and mod-36 check character |
| Bank account | 9–18 digits when the nearest label is an account label; IBANs by their mod-97 check |
| CVV, OTP, PIN | the value after its label |
| UPI ID | `name@handle` with a known UPI handle |
| Phone, email, DOB, passport, voter ID, IFSC | format plus nearby label |
| Names | after titles (Mr., Smt., Dr.) or labels such as "customer name" |
| Secrets | AWS keys, private keys, GitHub tokens, JWTs, passwords |
| Your own IDs | regular expressions in `policy.toml` |

## Roles

Each employee or app gets its own gateway key (`python -m privgate.ops keygen`). The key decides the user and role; identity headers in the request are ignored.

| Role | Can see |
|---|---|
| `support` | names and contact details |
| `fraud_analyst` | also PAN, card and Aadhaar |
| `developer` | nothing restored |
| `auditor` | the audit log only |

A conversation belongs to the user who started it, and nobody else can continue it or restore its values.

## Results

On 600 generated tickets, the gateway's precision for Aadhaar, card and account numbers is 0.98–1.00, against 0.17–0.45 for plain regular expressions.

On 2,891 held-out documents from Gretel's financial PII dataset, it masks 37.5% of the identifiers it targets, up from 12% before tuning on the train split. It handles IBANs (99%) and phone numbers (79%) well, but finds only 23% of names. Full tables are in [docs/evaluation.md](docs/evaluation.md).

## Configuration

| Variable | Purpose |
|---|---|
| `PRIVGATE_ENV=production` | refuse to start without keys, a database and provider credentials |
| `PRIVGATE_KEYS_FILE` | hashed gateway keys and the user and role for each |
| `PRIVGATE_VAULT_KEY` | AES-256 key for the vault |
| `PRIVGATE_AUDIT_KEY` | HMAC key for the audit log |
| `PRIVGATE_DATABASE_URL` | `sqlite:///...` or `postgresql://...` |
| `PRIVGATE_POLICY` | path to the policy file |
| `ANTHROPIC_API_KEY` or `PRIVGATE_UPSTREAM_URL` | provider credentials, or an internal proxy |

The full list, key rotation and backups are covered in [docs/runbook.md](docs/runbook.md). A container image is built with `docker build -t llm-privacy-gateway .`.

## Limitations

- Streaming responses are not proxied yet.
- Names without a title or label are usually missed. Adding a named-entity model in `privgate/detect.py` is the biggest improvement available.
- Images and PDFs are refused by default because they cannot be scanned as text.
- Rate limits are per process; use a shared limiter when running several replicas.
- The code has not had an independent security review. Before handling real customer data it also needs keys in an HSM or KMS, single sign-on instead of static keys, and approval under the bank's data protection rules.

See [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md).
