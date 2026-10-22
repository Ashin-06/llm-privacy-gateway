# LLM Privacy Gateway

Bank staff paste customer tickets, statements and call notes into AI assistants every day. This gateway sits between them and the AI provider. Before a prompt leaves the bank, it masks or blocks every Indian-banking identifier in it. It puts the real values back in the reply only for roles allowed to see them, catches identifiers the model makes up on its own, and writes a tamper-evident audit trail of every exchange.

It speaks the Anthropic Messages API, so existing code only changes its `base_url`.

```
employee / app ──► gateway ──(sanitised)──► Claude
                     │  ▲
                     │  └── placeholders restored per role, leaks in the reply masked
                     └── encrypted vault · policy · hash-chained audit
```

## Detection that validates, not just matches

| Type | How it is confirmed |
|---|---|
| Aadhaar | 12 digits, first 2–9, **Verhoeff check digit**. Labelled Aadhaar with a bad check digit is still caught, at lower confidence. |
| Card | 13–19 digits, **Luhn** plus a known **network prefix** (Visa, Mastercard, RuPay, Amex, Diners) |
| PAN | `AAAAA9999A` with a valid **holder-type** letter (P, C, H, F, A, T, B, L, J, G) |
| GSTIN | state code + PAN + **mod-36 check character** |
| Bank account | 9–18 digits only when the *closest* label before it is an account label (a/c, account no, beneficiary...), not UTR / order / ticket / phone |
| CVV, OTP, PIN | value after the label (`otp is 482913`, `cvv: 123`) |
| UPI ID | `name@handle` with a real PSP handle (okaxis, ybl, paytm...), not email addresses |
| Phone, email, DOB, passport, voter ID, IFSC | format plus context |
| Names | honorifics (Mr., Smt., Dr.) and labels (customer name, beneficiary, applicant, nominee) |
| Secrets | AWS keys, private-key blocks, GitHub tokens, JWTs, API keys, `password=` |
| Your own IDs | regexes in `policy.toml` (`CIF12345678`, loan numbers...) |

Benchmark (`python -m privgate bench`, 600 generated support tickets, chat logs and call notes, including look-alike negatives: order ids, UTRs, tracking numbers, PO numbers):

| Type | Gateway precision / recall | Naive regex precision / recall |
|---|---|---|
| Aadhaar | 0.984 / 1.000 | 0.195 / 1.000 |
| Card | 1.000 / 1.000 | 0.445 / 1.000 |
| Bank account | 1.000 / 0.988 | 0.172 / 1.000 |
| PAN, GSTIN, IFSC, UPI, phone, email, OTP, CVV, DOB, names | 1.000 / 1.000 | mostly not detected |

The naive detector treats every 12-digit number as Aadhaar and every 16-digit number as a card. That is why typical DLP rules swamp teams with false positives, or get switched off. Checksums and label proximity fix it. The corpus comes from templates, so expect lower recall on free-form text, especially names; see Limits.

## What happens to each value (`policy.toml`)

| Action | Effect | Default for |
|---|---|---|
| `tokenize` | reversible placeholder, stable within a conversation: `[[PAN_1]]`, `[[CARD_1:1111]]` (last 4 as a hint) | Aadhaar, card, PAN, account, phone, email, UPI, DOB, names, passport, voter ID, custom IDs |
| `block` | whole request refused with HTTP 422 | CVV, OTP/PIN, secrets |
| `redact` | irreversible `[REDACTED:TYPE]` | — |
| `allow` | passes through | IFSC, GSTIN (public) |

Originals are kept per conversation in an **AES-256-GCM vault**. The conversation id is bound as authenticated data, so a placeholder from one conversation can't be decrypted in another. Mappings expire after an hour. **Roles** decide what comes back:
- `support` sees names and contact details.
- `fraud_analyst` also sees PAN, card and Aadhaar.
- `developer` sees nothing.

The policy also lists **approved models**, a request size limit, and whether images or documents (which can't be text-scanned) are refused.

## The model's reply is checked too

If the model produces an identifier that didn't come from a placeholder (it guessed, completed or made one up), the gateway masks it before the reply reaches the employee and records it in the audit as `leaks_in_reply`.

## Use it

```bash
pip install -r requirements.txt
python -m pytest -q                      # 9 tests, including full proxy round-trips with a stub model
python -m privgate serve                 # gateway + playground on http://127.0.0.1:8010
python -m privgate scan ticket.txt       # what would be detected
python -m privgate mask ticket.txt       # sanitised text
python -m privgate bench
```

Point the Anthropic SDK at the gateway:

```python
import anthropic

client = anthropic.Anthropic(
    base_url="http://127.0.0.1:8010",
    api_key="<gateway key issued to this employee or app>",   # not an Anthropic key
)
reply = client.messages.create(
    model="claude-opus-5-5",
    max_tokens=2000,
    messages=[{"role": "user", "content": ticket_text}],
)
```

To keep placeholders stable across turns, reuse the `x-privgate-conversation` value returned in the first response header.

The gateway calls Anthropic with its own credentials (`ANTHROPIC_API_KEY` on the gateway host), so employees never hold the key.

### Who is calling

Issue each employee or app a **gateway key** and list them in `PRIVGATE_KEYS_FILE` (or the `PRIVGATE_API_KEYS` variable):

```json
{"k-7f3c...": {"user": "agent.meera", "role": "support"},
 "k-91aa...": {"user": "ravi.k", "role": "fraud_analyst"}}
```

- The key decides the user and role. `x-privgate-user` / `x-privgate-role` headers are ignored, so nobody can promote themselves to a role that sees more.
- A conversation belongs to the user who started it. Another user can't continue it or restore its values, even with a broader role.
- Keys are held in memory only as SHA-256 hashes. `/v1/messages`, `/v1/sanitize`, `/v1/restore` and `/v1/audit` all require one.
- **With no keys configured the gateway runs in demo mode:** the identity headers are trusted, which is fine for the local playground and nothing else. `GET /healthz` shows which mode is active.

| Setting | Purpose |
|---|---|
| `PRIVGATE_KEYS_FILE` / `PRIVGATE_API_KEYS` | gateway keys and the identity each one carries (see above) |
| `PRIVGATE_VAULT_KEY` | base64 AES-256 key, so placeholders survive restarts and work across replicas (default: random per process) |
| `PRIVGATE_AUDIT_KEY` | HMAC key for the audit chain |
| `PRIVGATE_AUDIT_LOG` | audit file path (default `data/audit.jsonl`) |
| `PRIVGATE_POLICY` | policy file |
| `PRIVGATE_UPSTREAM_URL` | alternative upstream (an internal proxy, for example) |

The **playground** at `/` shows each step on a sample ticket:
1. The prompt as the employee wrote it.
2. What was detected, colour-coded by action.
3. Exactly what the AI provider receives.
4. A model reply restored for each role.

It also shows the live audit trail with chain verification. Nothing in the playground calls a model.

## Audit

Every request records:
- user, role, conversation, model
- counts per type and action (`PAN:tokenize×1`), never the values
- restorations, leaks in the reply, stop reason, latency
- blocked and rejected requests

Entries are hash-chained (HMAC-keyed when `PRIVGATE_AUDIT_KEY` is set). Editing, deleting or reordering one breaks `/v1/audit` verification.

## Limits

- **Streaming isn't proxied yet.** Placeholders can split across chunks, so the gateway asks for `stream: false`.
- **Name detection uses labels and honorifics.** For free-form text, add an NER model (spaCy or a fine-tuned IndicBERT) in `detect.py`. The rest of the pipeline stays the same.
- **Images and PDFs are refused by default**, because they can't be text-scanned. Put OCR in front, or set `allow_binary` if your policy allows it.
- **The vault is in memory.** For several replicas, back it with Redis using the same AES-GCM sealing, and share `PRIVGATE_VAULT_KEY`.
