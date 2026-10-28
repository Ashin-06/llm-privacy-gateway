# Evaluation

## Generated tickets

`python -m privgate bench` runs the detector over 600 generated support tickets, chat logs and call notes. The set includes look-alike numbers that must not be masked: order IDs, UTRs, tracking numbers and PO numbers.

| Type | Gateway precision / recall | Plain regex precision / recall |
|---|---|---|
| Aadhaar | 0.984 / 1.000 | 0.195 / 1.000 |
| Card | 1.000 / 1.000 | 0.445 / 1.000 |
| Bank account | 1.000 / 0.988 | 0.172 / 1.000 |
| PAN, GSTIN, IFSC, UPI, phone, email, OTP, CVV, DOB, names | 1.000 / 1.000 | mostly not detected |

A plain regex treats every 12-digit number as an Aadhaar number and every 16-digit number as a card, which is why simple DLP rules produce so many false alarms. Check digits and the label closest to the number remove most of them. The tickets come from templates, so recall on free-form text is lower, especially for names.

## Realistic financial documents

[Gretel's synthetic financial PII dataset](https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual) (Apache-2.0) contains loan applications, SWIFT messages, statements and claims about invented people, with every identifier labelled. Real customer documents can't be published, so this is the closest available test. Most documents are US or European, so they include formats beyond the Indian ones the gateway was built for.

`python -m privgate realdata` writes `results/real_data.json`.

The first run masked 12% of the identifiers the gateway targets. Patterns were then added using a sample of the train split only. The numbers below are on the held-out test split (2,891 English documents).

| Identifier | Labelled | Masked before → after |
|---|---|---|
| IBAN | 69 | 9% → 99% |
| Email | 330 | 95% → 95% |
| Date of birth | 126 | 54% → 83% |
| Phone | 480 | 2% → 79% |
| Card number | 83 | 52% → 78% |
| Passport | 76 | 1% → 54% |
| Card security code | 76 | 0% → 38% |
| Bank PIN | 80 | 41% → 41% |
| BBAN | 93 | 13% → 39% |
| Names | 3,730 | 4% → 23% |
| API keys, passwords | 101 | 21% → 22% |
| All targeted identifiers | | 12% → 37.5% |

About 65% of what the gateway masks falls on a labelled identifier. The labels miss some PII, so the true precision is higher than that. The generated-ticket benchmark above did not change after these additions.

Names are the main gap: most names in ordinary prose have no title or label next to them. US SSNs, driver's licences, street addresses, routing numbers and company names are not targeted; add them in `policy.toml` if your traffic contains them.
