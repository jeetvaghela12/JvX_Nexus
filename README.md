# RemitCore

**Cross-border compliance infrastructure for Indian banks.**

RemitCore is a data and compliance layer that runs behind a bank's own application, so the bank's customers — freelancers, remote employees on foreign payroll, IT agencies and small exporters — can receive international payments without leaving for PayPal, Wise or Skydo.

The bank keeps the app, the brand, the money and the customer. RemitCore never holds funds and never contacts the end customer.

> Working prototype, running against mock provider credentials. Not in production. No bank partnership yet.

---

## The problem

An Indian freelancer invoices a US client. Through her own bank she loses 2–5% to FX markup and fees, has no visibility once the money is sent, and spends days chasing a FIRA certificate for her tax filing.

So she leaves for a fintech platform. The bank loses the FX income — and, more importantly, loses all visibility into her cash flow, and with it any basis to lend to her later.

Skydo alone has onboarded 40,000+ businesses and crossed $1bn in annualised volume. That money settles outside the banking channel entirely.

---

## What RemitCore does

| | RemitCore | Bank |
|---|---|---|
| Sign up / sign in | Stores credentials, issues token | — |
| KYC | Confirms existing status | Approves — already their customer |
| Account issued | Requests it, surfaces it on the dashboard | Issues it through its own escrow rail |
| Invoice | Uploaded, fingerprinted, duplicate-checked | Reviews it |
| Declaration / receipt | Generated automatically, reference attached | Reads it, keeps it on file |
| Money arrives | Recorded the moment the bank reports it | Holds it in its own escrow throughout |
| Settlement | Status updated on the dashboard | Converts, credits INR, files with RBI, issues FIRA |

**We pass data. The bank holds money.** Every step that touches funds, identity or a regulator belongs to the bank.

---

## Why no licence is required

A Payment Aggregator — Cross Border (PA-CB) authorisation applies to entities that collect and settle funds on a merchant's behalf. RemitCore does neither.

We are a technology service provider to a regulated entity. Our obligations sit under the **RBI (Outsourcing of IT Services) Directions, 2023** — meaning the real gate is the bank's own vendor due diligence: VAPT, ISO 27001, data localisation, BCP/DR, audit rights and source code escrow.

There is deliberately **no settlement engine in this codebase.** An earlier design had one; it was removed, because holding or moving funds would change what this product legally is.

---

## Architecture

```
Customer (bank's app)  →  RemitCore (data layer)  →  Bank's backend (money, decisions)
```

**Stack:** Python · FastAPI · SQLAlchemy · PostgreSQL

```
api/          Route handlers — auth, kyc, van, invoices, declarations, payments, b2b
core/         Config, database, security, encryption, dependencies
models/       SQLAlchemy models
schemas/      Pydantic request/response schemas
services/     Bank webhook processing, compliance engine, file storage
```

---

## Engineering notes

A few decisions worth explaining, since they are not obvious from the code alone.

**Idempotent payment recording.** `bank_reference` is a unique column. Banks redeliver webhooks — on timeout, on retry, on an operator pressing resend. A replayed signal finds the existing row and returns it rather than recording the same money twice. The constraint is the guarantee; the lookup is the fast path.

**Signature verification before parsing.** HMAC-SHA256 is computed over the raw request bytes and checked *before* the JSON is parsed. A signature verified after parsing has already let a forged payload through the parser. This is why the webhook routes take `Request` rather than a typed Pydantic body.

**`hmac.compare_digest`, never `==`.** A plain string comparison returns as soon as it finds a mismatched byte, which leaks how many leading bytes were correct. Repeated, that recovers a valid signature one byte at a time.

**Dual-hash duplicate detection.** A SHA-256 file hash catches an identical resubmission. A separate content fingerprint over normalised fields catches a re-saved copy of the same invoice — something a file hash alone would miss. Pre-check for the readable error; unique constraint plus `IntegrityError` catch as the actual guarantee, since two concurrent uploads both pass the pre-check.

**Decimal everywhere, never float.** All money columns are `Numeric(18,4)`. Values parsed from JSON go through `str` first, because `Decimal(float)` preserves the binary representation error exactly.

**Magic-byte file validation.** Uploaded files are checked by their actual leading bytes, not by `content_type`, which is caller-supplied and trivially spoofed.

**Field-level encryption.** Government identification numbers are encrypted with AES-256-GCM at the column level, not only at the disk layer.

**Conservative declaration matching.** If an inbound payment matches two open pre-declarations, it matches neither and logs why. A wrong match files an unintended purpose code with RBI on a coin flip; leaving it unmatched is the status quo and harms nothing.

---

## Running locally

Requires Python 3.12+ and PostgreSQL.

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file:

```env
DATABASE_URL=postgresql://user:password@localhost:5432/dbname
JWT_SECRET=
BANK_WEBHOOK_HMAC_SECRET=
KYC_VERIFICATION_WEBHOOK_SECRET=
FIELD_ENCRYPTION_KEY=
```

Generate the secrets:

```bash
# JWT_SECRET, BANK_WEBHOOK_HMAC_SECRET, KYC_VERIFICATION_WEBHOOK_SECRET
python -c "import secrets; print(secrets.token_urlsafe(48))"

# FIELD_ENCRYPTION_KEY — must be a Fernet key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Use a different value for each secret. Losing `FIELD_ENCRYPTION_KEY` makes every encrypted field permanently unreadable.

```bash
python reset_db.py              # drops tables — development only
uvicorn main:app --reload
```

API docs at `http://127.0.0.1:8000/docs`.

A Streamlit reference dashboard is included:

```bash
streamlit run demo_app.py
```

---

## Status

| | |
|---|---|
| Auth, MFA, JWT | Working |
| Invoice upload + duplicate detection | Working, tested |
| Declarations (pre-payment and self-declaration) | Working |
| Webhook verification and payment recording | Working |
| Field-level encryption | Working |
| KYC and virtual account coordination | Mock credentials |
| AML screening | Mock data |
| Bank partnership | None yet |
| Production deployment | None yet |

Schema changes use `reset_db.py`, which drops everything. There is no Alembic setup — `create_all()` is additive and will silently skip a column added to an existing table.

---

## Roadmap

**Near term** — incorporation, legal opinion confirming the no-licence position, integration against a bank's public developer sandbox.

**After that** — VAPT from a CERT-In empanelled auditor, security architecture review, ISO 27001 gap assessment.

**Then** — closed-loop proof of concept with one partner bank.

---

## License

Not currently licensed for reuse. Please open an issue if you want to discuss it.

## Contact

Jeet Vaghela · Junagadh, Gujarat
[LinkedIn](https://www.linkedin.com/in/jeetvaghela12) · [GitHub](https://github.com/jeetvaghela12)