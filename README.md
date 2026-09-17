# JvX Nexus

**Compliance-first infrastructure for Indian freelancers, IT agencies, and small service exporters receiving foreign payments.**

JvX Nexus is a pure technology layer — it never holds funds. Every payment moves through a licensed AD-1 bank or PA-CB partner. JvX handles the risk logic, the documentation, and the client-side verification that sits around that payment.

---

## The Problem

A 2018 PayPal survey of 500 Indian freelancers found 61% had gone unpaid by a client at least once. RBI data shows India's software-service exports hit $180.6 billion in FY25, growing 12.7% — RBI's own economists attribute part of that growth specifically to individual freelancers, not just large IT firms. And the Income Tax Department's NUDGE enforcement campaign has already recovered over ₹800 crore in tax from undisclosed foreign income and assets.

Three separate, documented problems, one underserved population:
1. Freelancers can't easily vet a new client before doing unpaid work for them.
2. Payment platforms screen for fraud and sanctions *after* money lands — documented complaints (Skydo, Payoneer) describe accounts frozen post-receipt.
3. Foreign income scattered across platforms means missing tax documentation, discovered too late.

---

## Architecture — Three Pillars

### Pillar 1 — JvX Core
**Pre-transaction fraud and sanctions screening.** Screens a payment for fraud and sanctions *before* it settles, not after.

- JWT authentication with TOTP-based multi-factor auth
- KYC: PAN verification (Cashfree integration), IEC handling, GST optional under ₹20L turnover, AML screening against UAPA/OFAC/UN/EU watchlists
- Virtual Account Number issuance (Decentro integration)
- **Dual-hash invoice fraud detection** — SHA-256 file hash plus a separate content fingerprint, both checked for global uniqueness before an invoice is accepted. Confirmed working end-to-end in a live demo.
- HMAC-SHA256 bank webhook verification, checked against raw request bytes before JSON parsing
- Idempotent settlement dispatch — unique-constraint idempotency keys, `SELECT FOR UPDATE` row locking for concurrency safety, automatic retry sweep for stuck settlements
- AES-256-GCM field-level encryption for government ID numbers
- All monetary values as `Numeric(18,4)` Decimal — never floating-point

**Status:** Core auth, invoice fraud detection, and the settlement pipeline are built and tested. KYC and VAN issuance run against mock provider credentials — no live bank partnership yet. No live cross-border CBDC corridor exists for anyone at this time; the routing architecture is CBDC-ready but not operational.

### Pillar 2 — JvX Consolidator
**Cross-platform foreign income documentation.** Pulls income from every source a freelancer has — Upwork, AdSense, direct clients — into one place, and flags which records are missing proof before tax season, not during it.

- Income logging across multiple source types
- Gap detection: identifies which income records lack supporting documentation
- Self-declared receipt generation for income with no formal proof available — clearly labeled as self-declared, never presented as an official bank document, and blocked from generation if real proof already exists
- AdSense OAuth integration for automatic income sync (Google app verification in progress)
- CA-ready export: consolidates all income and documentation into one bundle

**Status:** Code complete and integrated; in active testing.

### Pillar 3 — JvX ClientShield
**Pre-engagement client risk screening.** Checks a prospective client's legitimacy before a freelancer does unpaid work for them — the one part of this space with no direct competitor.

- Domain age check (RDAP, keyless)
- Business registry checks (UK Companies House, GLEIF LEI)
- MX record / email infrastructure validation (keyless)
- Disposable email detection
- Google Web Risk threat intelligence
- Weighted risk scoring: a sanctions hit auto-overrides to HIGH risk; otherwise, signals are weighted and combined into LOW/MEDIUM/HIGH, with full reasoning returned alongside every score

**Status:** Code complete and integrated; in active testing.

---

## Why This Architecture

**JvX never holds funds.** It is a technology layer that sits on top of a licensed AD-1 bank or PA-CB partner, which holds custody and carries regulatory liability. This is a deliberate, load-bearing design choice — not a limitation.

**Every claim in this repo is stated at the confidence level it deserves.** "Built and tested" means exactly that. "Mocked" means real integration code exists but runs against placeholder credentials, not a live provider. This distinction is maintained throughout the codebase and this document, not just in the pitch materials that reference it.

---

## Tech Stack

- **Backend:** FastAPI, SQLAlchemy 2.0 (`Mapped`/`mapped_column`), PostgreSQL
- **Frontend/Dashboard:** Streamlit
- **Cloud:** AWS S3 for audit trail storage, AWS Textract for invoice data extraction
- **Auth & Security:** JWT, TOTP, bcrypt, AES-256-GCM field-level encryption
- **External integrations:** Cashfree (KYC), Decentro (VAN issuance), RDAP, GLEIF, UK Companies House, Google Web Risk

---

## Regulatory Positioning

JvX Nexus operates as a technology-orchestration layer, not a licensed payment entity. This understanding — that a pure technology layer sits outside direct RBI/PA-CB licensing since it never holds funds — is the working design assumption, not a confirmed legal position. Independent legal and regulatory review is a genuine next step.

---

## What's Next

- Real bank/PA-CB partnership for Pillar 1's live settlement flow
- Complete testing on Pillar 2 and Pillar 3
- Real users for ClientShield, since it requires no bank partnership or license to be genuinely useful today
- Independent legal review of the technology-layer positioning

---

*Built solo by Jeet Vaghela. A focused, hackathon-built prototype of ClientShield — developed in 22 hours at the GIFT IFIH Young Builders' Program Hackathon — lives in a separate repository, `jvx-nexus-hackathon`.*
