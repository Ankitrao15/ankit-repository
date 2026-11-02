# Ankit Yadav — Portfolio & Engineering Showcase

Personal portfolio web application for **Ankit Yadav** (Python Developer | Backend | REST APIs | Generative AI), featuring real-time GitHub profile and repository synchronization (`Ankitrao15`), high-thinking architecture analysis (`gemini-4-argon`), and a 5-stage security & privacy compliance architecture.

## Security & Git History Warning (Gitleaks Compliance)

> **CRITICAL GIT HISTORY WARNING**: If any API key, token, database URI, or credential was ever previously hardcoded or committed in earlier snapshots of your repository, removing it from the working tree does **not** erase it from git history. **Rotate any previously hardcoded secrets immediately** in your provider console (Google AI Studio Secrets, GitHub Personal Access Tokens, database credentials) and purge historical commits using `git filter-repo` or BFG Repo-Cleaner before making the repository public.

## 5-Stage Security Audit Summary

1. **Prompt 1 — Secret Leak Prevention (Gitleaks)**:
   - Zero hardcoded API keys, tokens, or credentials exist anywhere in the client or server codebase.
   - All sensitive variables (`GEMINI_API_KEY`, `GITHUB_TOKEN`, `SESSION_SIGNING_SECRET`) are read strictly on the server via `process.env` and never prefixed with `VITE_`, `REACT_APP_`, or `NEXT_PUBLIC_`.
   - `.env` is gitignored and `.env.example` contains safe placeholder templates.

2. **Prompt 2 — Personal Data Flow Audit (Bearer)**:
   - **Data Collection**: Contact form collects `name`, `email`, and `message`.
   - **Zero PII Logging**: Server logs pass through `redactPII()`, replacing emails, phone numbers, and bearer tokens with `[REDACTED]`.
   - **No Client-Side PII Storage**: No personal data is stored in `localStorage` or unencrypted cookies.
   - **Field-Level Filtering & GDPR Right to Erasure**: Contact endpoints return only minimal receipt metadata (`receiptId`, `submittedAt`, `maskedEmail`) and provide a cryptographic `deletionToken` enabling immediate self-service erasure via `DELETE /api/contact/:receiptId`.

3. **Prompt 3 — Pre-Deploy Production Audit (ECC)**:
   - Strict HTTP security headers applied to every response (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security: max-age=31536000; includeSubDomains`, `Content-Security-Policy`, `Referrer-Policy: strict-origin-when-cross-origin`).
   - Per-IP rate limiting enforced on contact submissions (5 requests/minute), data deletion (5 requests/minute), and AI analysis endpoints (10 requests/minute).
   - Correlation IDs (`X-Correlation-ID`) returned on errors with zero stack trace or file path leakage.

4. **Prompt 4 & 5 — Deep Logic & Attacker's Perspective Audit (Trail of Bits / ECC)**:
   - Strict input sanitization (`sanitizeInput`) strips HTML/script tags and blocks SQLi/XSS payloads before processing.
   - Ownership verification via single-use HMAC-signed deletion tokens prevents IDOR (`DELETE /api/contact/:receiptId` requires the matching owner token).
   - Server blocks direct URL access to sensitive paths (`/.env`, `/.git`, `/server.ts`).
