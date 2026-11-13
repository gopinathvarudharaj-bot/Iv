# PhishShield AI Security Specification

## 1. Data Invariants
1. **Strict Owner Isolation (PII & Private Scans)**: `/users/{userId}`, `/userPreferences/{userId}`, `/scans/{scanId}`, and `/reports/{reportId}` are strictly owned by `request.auth.uid`. Cross-user reads, lists, writes, or deletes are unconditionally denied.
2. **Verified Identity Enforcement**: All write operations require `request.auth != null && request.auth.token.email_verified == true`.
3. **Referential Integrity**: `/userPreferences/{userId}`, `/scans/{scanId}`, and `/reports/{reportId}` cannot be created unless the parent `/users/{request.auth.uid}` profile document exists.
4. **Immutable Ownership, Scan Inputs & Creation Timestamps**: `uid` / `userId`, `id`, `scanType`, `rawInput`, `targetPreview`, `isDemoMode`, and `createdAt` are immutable after creation (owners may only update `archived`/`analystNote` or re-scored deterministic verdict/ML fields).
5. **Temporal Integrity**: `createdAt` must equal `request.time` on creation; `updatedAt` must equal `request.time` on update.
6. **Bounded Resource Sizes & Enum Safety**: All strings have explicit `.size()` ceilings (including `submittedUrl <= 2000`, `reputationProvider <= 120`, `reputationCheckedAt <= 64`, `mlSummary <= 300`, `mlProbability` `0..100`), arrays are capped (`indicators <= 20`, `recommendations <= 15`, `threatCategories <= 10`), and `riskLevel`, `reputationResult`, `scanType`, `sensitivity`, `format` (`pdf`, `json`, `markdown`) are strictly allowlisted. Unknown URLs cannot be stored as `"Safe"`.
7. **Zero Client Query Delegation**: `allow list` on `/scans` and `/reports` explicitly checks `resource.data.userId == request.auth.uid`. Blanket `allow list` on `/users` and `/userPreferences` is disabled.
8. **Zero Cloud Storage / Spark-Plan Isolation**: QR images are decoded locally in the browser, threat reputation API keys remain strictly server-side, and reports are exported directly in the browser without Firebase Cloud Storage.
9. **Strict Privacy & Data Minimization**: `/users/{uid}` stores only minimal `uid`, `displayName`, and timestamps (no redundant `email`/`photoURL` PII on create/update). `/scans/{scanId}` enforces `^[REDACTED_(EMAIL|SMS)_META]` for `email`/`sms` records (original SMS messages, email contents, sender PII, and passwords are never persisted) and blocks `data:image/` payloads so uploaded QR images are never saved to Firestore.

## 2. The Adversarial Payloads
1. **Unauthenticated Write**: Creating `/scans/scan_01` when `request.auth == null` -> `PERMISSION_DENIED`.
2. **Unverified Email Write**: Creating `/scans/scan_02` with `request.auth.token.email_verified == false` -> `PERMISSION_DENIED`.
3. **Cross-User Identity Spoofing**: User `alice` attempting to create `/scans/scan_03` with `userId: "bob"` -> `PERMISSION_DENIED`.
4. **Cross-User List Scraping**: User `alice` querying `/scans` without filtering to `userId == "alice"` -> `PERMISSION_DENIED`.
5. **PII Blanket Read**: User `alice` calling `get(/users/bob)` -> `PERMISSION_DENIED`.
6. **Ghost / Shadow Field Injection**: Creating `/userPreferences/alice` with an undeclared field `isAdmin: true` -> `PERMISSION_DENIED`.
7. **Invalid Document ID Poisoning**: Creating `/scans/bad$id/with/..chars` or 200-char ID -> `PERMISSION_DENIED`.
8. **Timestamp Forgery**: Creating `/scans/scan_04` with a backdated `createdAt` instead of `request.time` -> `PERMISSION_DENIED`.
9. **Immutable Owner Tampering**: Updating `/scans/scan_05` to change `userId` from `alice` to `bob` -> `PERMISSION_DENIED`.
10. **Invalid Risk Classification ("Safe" Claim)**: Creating `/scans/scan_06` with `riskLevel: "Safe"` -> `PERMISSION_DENIED`.
11. **Array / Payload Exhaustion**: Creating `/scans/scan_07` with 50 indicators or a 50KB `rawInput` string -> `PERMISSION_DENIED`.
12. **Orphaned Scan Creation**: Creating `/scans/scan_08` before `/users/{uid}` exists -> `PERMISSION_DENIED`.
13. **Raw SMS/Email Content Persistence**: Creating `/scans/scan_09` with `scanType: "sms"` and unredacted `rawInput: "Your OTP is 123456"` -> `PERMISSION_DENIED`.
14. **Embedded Image Persistence**: Creating `/scans/scan_10` with `rawInput: "data:image/png;base64,iVBORw0..."` -> `PERMISSION_DENIED`.

