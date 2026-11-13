# PhishShield AI

PhishShield AI is a full-stack phishing and scam inspection dashboard built with React, TypeScript, Tailwind CSS, Express, server-side Gemini AI, and the free **Firebase Spark plan** (Firebase Authentication + Cloud Firestore only — **no Firebase Cloud Storage or billing account required**).

## Architecture & Key Features

- **Spark-Plan Firebase Integration (Auth + Firestore Only)**:
  - **Firebase Authentication**: Supports Email/Password registration + login (with email verification enforcement) and Google Sign-In (`signInWithPopup`) with `browserLocalPersistence`.
  - **Cloud Firestore Data Minimization**: Stores only minimal user reference metadata (`/users/{uid}` without redundant `email` or `photoURL`), scanner preferences (`/userPreferences/{uid}`), sanitized scan history & security verdicts (`/scans/{scanId}`), and report metadata (`/reports/{reportId}`) with strict owner isolation enforced in `firestore.rules`. Original SMS messages, email contents, sender addresses, uploaded QR image bytes, and passwords/tokens are **never** stored in Firestore.
  - **Zero Cloud Storage Dependency**: QR images and exported reports are processed locally in the browser and never uploaded to Firebase Storage or any paid cloud bucket.
- **Static URL Scanner & Server-Side TypeScript Feature Model**: Inspects URLs lexically for typosquatting (Damerau-Levenshtein edit distance, repeated characters, Unicode/ASCII homoglyphs), IP hosts, punycode/IDN, suspicious characters, and credential-lure paths without ever opening, crawling, or redirecting to submitted URLs. Combines deterministic weighted heuristics with a server-side TypeScript logistic lexical feature scorer (`PhishShield-TS-FeatureModel-v2`), kept strictly separate from live threat reputation results. Unknown or unverified URLs are never classified as `"Safe"`.
- **Official Threat Reputation Provider (Google Safe Browsing API v4)**: Server-side `/api/analyze/*` and `/api/scans/rescore` routes query `safebrowsing.googleapis.com/v4/threatMatches:find` using the server-only `GOOGLE_SAFE_BROWSING_API_KEY` secret (`x-goog-api-key` header) and return three distinct reputation outcomes: `Known Malicious` (with threat categories), `No Known Threat Found` (with explicit caution that absence of a match does not mean safe), and `Unknown / Unverified` (on missing credentials, timeouts, quota/rate limits, or service outages). Stored in Cloud Firestore alongside `submittedUrl`, `reputationProvider`, `reputationCheckedAt`, and `threatCategories`.
- **Email / SMS Scanner**: Analyzes urgency coercion, credential/OTP harvesting requests, impersonation phrases, and embedded URLs transiently, then strips original message bodies and sender PII (`[REDACTED_EMAIL_META]` / `[REDACTED_SMS_META]`) before saving security findings to Cloud Firestore.
- **Local Browser QR Code Scanner**: Decodes QR image pixels (`PNG`, `JPG`, `WebP`) strictly inside the browser via `jsQR` and HTML5 `<canvas>` and redacts Wi-Fi/URL credentials before persistence. Uploaded images never leave the user's browser.
- **Browser-Direct Report Generation (`PDF`, `JSON`, `Markdown`)**: Generates and downloads `.pdf` (via `jspdf`), `.json`, and `.md` security reports directly in the browser while optionally saving report metadata to Cloud Firestore.
- **Optional Server-Side Gemini AI Assistant**: Uses `gemini-4-hydrogen` through Express `/api/*` endpoints via `@google/genai`, keeping `GEMINI_API_KEY` strictly on the server. Includes 3-attempt exponential backoff with jitter for transient 503/timeout failures, avoids retrying 400/401/403/404/429 errors blindly, never fabricates fallback AI output, and preserves heuristic scan results with a **Retry AI Explanation** button when temporarily unavailable.

## Environment Configuration

See `.env.example`:

- `GEMINI_API_KEY`: Optional server-side Gemini API key (configured via runtime secrets; never exposed to client bundles).
- `GOOGLE_SAFE_BROWSING_API_KEY`: Optional server-side Google Safe Browsing API v4 key (configured via runtime secrets; never exposed to client code). When missing, the UI clearly shows reputation checking is not configured and returns `Unknown / Unverified`.
- `GOOGLE_SAFE_BROWSING_TIMEOUT_MS`: Optional Safe Browsing request timeout in ms (default `8000`).
- `APP_URL`: Runtime application URL.

Firebase client configuration is stored in `firebase-applet-config.json` (Authentication + Cloud Firestore database ID). No external ML server, Firebase Cloud Storage bucket, or billing plan is required.

## Firestore Security & Data Isolation

- Unauthenticated reads, queries, and writes are denied across `/users`, `/userPreferences`, `/scans`, and `/reports`.
- Writes require `request.auth != null && request.auth.token.email_verified == true`.
- Every document enforces strict owner matching (`userId == request.auth.uid`), bounded string/array limits, immutable ownership & `createdAt` timestamps, strict data-minimization rules (blocking `data:image/` payloads and unredacted `email`/`sms` bodies), and strict enum allowlists (`riskLevel` never allows `"Safe"`, `reputationResult` allows only `'Known Malicious'`, `'No Known Threat Found'`, `'Unknown / Unverified'`, report `format` allows only `'pdf'`, `'json'`, `'markdown'`).

## Commands

```bash
npm install
npm run dev      # Starts Express + Vite dev server on port 3000
npm run lint     # TypeScript type-check (tsc --noEmit)
npm run test     # Runs Gemini, URL scoring, mock reputation, and gated live reputation tests
npm run build    # Production Vite bundle build
```
