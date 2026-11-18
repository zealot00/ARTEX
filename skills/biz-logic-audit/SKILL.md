---
name: biz-logic-audit
description: "Invoke this skill when testing enterprise business applications for business-logic flaws: multi-role IDOR/BOLA, step-skipping state-machine bypasses, sensitive response field leaks (e.g. OTP/ticket leaked in pre-auth response), race conditions, and frontend JS request signing/encryption."
---

# Business Logic, Access Control & Race Condition Audit

## 1. Multi-Role Access Control & IDOR (`authz_replay`)
1. Capture or identify an authenticated business endpoint (`GET`/`POST`/`PUT`/`DELETE`).
2. Run `authz_replay(task_id, url, method, headers, body, low_priv_headers, include_bypasses=true)`:
   - Verifies **unauthenticated** access (all `Authorization` / `Cookie` / `X-Token` stripped).
   - Verifies **horizontal/vertical privilege escalation** when `low_priv_headers` are available.
   - Verifies path normalization (`..;/`) and proxy header (`X-Forwarded-For`, `X-Original-URL`) bypasses.
3. For IDOR on object IDs (`id`, `userId`, `orderId`, `fileId`, `tenantId`), test swapping at most 2–3 non-owned IDs and confirm actual unauthorized data is returned.

## 2. State-Machine Step Skipping & Response Secret Leaks
Inspect every multi-step workflow (login/OTP/SMS, password reset, registration, approval, payment/quota):
1. **Response Field Leak Check**: inspect JSON responses of Step 1 (e.g., `/send-sms`, `/init-login`, `/pre-check`) for leaked `ticket`, `code`, `otp`, `token`, `resetKey`, `userId`, or `internalFlag` that should never reach the client before verification.
2. **Direct Step Skipping**: test calling Step 2/3 directly with empty/arbitrary verification fields or with leaked Step 1 fields without completing the intermediate challenge.
3. **Client-Side Trust / Status Tampering**: test modifying `"status":"approved"`, `"step":3`, `"verified":true`, `"price":0`, or `"role":"admin"` in request bodies.

## 3. Concurrency & Race Conditions (`race_probe`)
For one-time actions (coupon redeem, approval submit, balance/quota deduction, invitation claim):
- Call `race_probe(task_id, url, method, headers, body, concurrency=8)` (automatically capped at 5 in `prod_safe_mode`).
- If multiple concurrent requests return `200 OK` / success body hashes for an action that should succeed only once, confirm the state change and report with measured count (`N of M succeeded`).

## 4. Encrypted / Signed Business APIs (JS Reverse Prep)
When an internal SPA encrypts payloads or sends `X-Sign` / `X-Signature` / `timestamp`:
- Inspect downloaded JS bundles (`skills/api-recon`) for crypto/signing helpers (`CryptoJS`, `AES`, `SM2`/`SM4`, `md5`/`hmac`, `interceptors.request.use`).
- Re-implement the exact signing/encryption flow inside a custom `python_script` executed via `run_poc(inline_kind="python_script", ...)` so subsequent fuzzing/IDOR probes carry valid signatures.
