# MYX AI (Windows Edition) — Authentication & Session Architecture

**Application:** MYX AI by Midhun Krishnan  
**Classification:** DEFENSIVE SECURITY ARCHITECTURE DOCUMENT  
**Document Revision:** 2.4.0-SEC  
**Date:** November 15, 2026  

---

## 1. High-Level Authentication Architecture

MYX AI implements a defense-in-depth, zero-trust server-side authentication and session architecture. All client-side authority assumptions have been removed. User credentials, sessions, and authorization states are managed authoritatively by the backend.

```
+-----------------------------------------------------------------------------------+
|                                 USER BROWSER                                      |
|                                                                                   |
|  +---------------------------+          +--------------------------------------+  |
|  |       AuthContext         |          |          CentralizedApiClient        |  |
|  | - Listens to /auth/me     |          | - Injects X-CSRF-Token on POST/PUT   |  |
|  | - Displays verified role  |          | - Passes credentials: 'include'      |  |
|  +-------------+-------------+          +-------------------+------------------+  |
+----------------|--------------------------------------------|---------------------+
                 |                                            |
                 | HTTP Requests with HttpOnly myx_session    |
                 v                                            v
+-----------------------------------------------------------------------------------+
|                            MYX AI BACKEND RUNTIME                                 |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |                      CORS Guard (Strict Origin Allowlist)                   |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
|                                        v                                          |
|  +-----------------------------------------------------------------------------+  |
|  |                       requireCsrf (Session-Bound Guard)                     |  |
|  |  - Validates client X-CSRF-Token matches session.csrfToken in constant-time |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
|                                        v                                          |
|  +-----------------------------------------------------------------------------+  |
|  |                     requireAuth (Session Token Validation)                  |  |
|  |  - Computes sha256(rawToken) and looks up in activeSessions store           |  |
|  |  - Validates 24-hour max TTL and 2-hour idle timeout                        |  |
|  |  - Binds verified user identity & role to req.user                          |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
|                                        v                                          |
|  +-----------------------------------------------------------------------------+  |
|  |                     requireRole(['ADMIN', 'SECURITY_ANALYST'])              |  |
|  |  - Enforces Role-Based Access Control matrix (HTTP 403 on denial)           |  |
|  +-----------------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

---

## 2. Password Hashing Specification

MYX AI enforces CPU- and memory-hard password hashing using the industry-standard `scrypt` key derivation function with dedicated per-account cryptographic salts.

### Parameters
- **Algorithm:** `scrypt`
- **CPU/Memory Cost ($N$):** $32,768$ ($2^{15}$)
- **Block Size ($r$):** $8$
- **Parallelization ($p$):** $1$
- **Key Length:** $64$ bytes ($512$ bits)
- **Salt Generation:** `crypto.randomBytes(32)` ($256$ bits of CSPRNG entropy)
- **Encoded Storage Format:** `scrypt:32768:8:1$<salt_hex>$<derived_key_hex>`

### Verification
During authentication:
1. The salt and expected derived key are unpacked from the stored format.
2. The user-provided password candidate is derived with identical parameters.
3. Both buffers are compared using `crypto.timingSafeEqual` to prevent side-channel timing attacks.

### Password Complexity Rules
Registration and credential rotation endpoints enforce:
- Minimum length: **10 characters**
- At least one uppercase Latin character (`A-Z`)
- At least one lowercase Latin character (`a-z`)
- At least one ASCII numeric digit (`0-9`)
- At least one special symbol (`[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]`)

---

## 3. Server-Side Session Store

Session state is maintained in a server-side hash map (`activeSessions`).

### Threat Model & Protections
1. **Database Breach Protection:** The database and in-memory store **never** store plaintext session tokens. Instead, the backend stores only the SHA-256 digest:
   $$\text{tokenHash} = \text{SHA-256}(\text{rawToken})$$
   A compromised memory snapshot or leaked database file cannot be used to forge active sessions.
2. **Session Lifetimes:**
   - **Absolute Expiration (Max TTL):** 24 hours (`SESSION_TTL_MS = 86,400,000 ms`).
   - **Sliding Inactivity Timeout:** 2 hours (`SESSION_IDLE_TIMEOUT_MS = 7,200,000 ms`). Every authenticated request updates `lastActiveAt`.
3. **Cookie Attributes:**
   - `HttpOnly`: Prevents client-side scripts (XSS payloads) from reading the session token.
   - `SameSite=Lax`: Prevents cross-site request leakage while permitting top-level navigation.
   - `Secure`: Transmitted only over encrypted TLS in production environments.
   - `Path=/`: Scoped to application endpoints.
4. **Session Revocation:**
   - On explicit logout (`POST /api/v1/auth/logout`), the session hash is deleted from `activeSessions` and a zero-max-age cookie is returned.
   - If an account is deactivated via `PATCH /api/v1/admin/users/:userId/toggle-active`, subsequent requests trigger immediate session termination (`ACCOUNT_DEACTIVATED`).

---

## 4. Session-Bound CSRF Architecture

1. **Token Generation:** Upon login or session creation, the server generates a cryptographically random 32-byte hexadecimal CSRF token (`session.csrfToken`).
2. **Token Distribution:** Transmitted to the client via custom response header `X-CSRF-Token` and JSON payload.
3. **Client Submission:** The centralized API client (`apiClient.ts`) automatically extracts this header and supplies it in the `X-CSRF-Token` request header on all state-changing HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`).
4. **Server Validation:**
   - Evaluated by `requireCsrf` middleware prior to controller execution.
   - Verified via `crypto.timingSafeEqual(Buffer.from(clientCsrf), Buffer.from(session.csrfToken))`.
   - Requests with missing or mismatched tokens are terminated with HTTP 403 (`CSRF_TOKEN_MISSING` / `CSRF_TOKEN_INVALID`).

---

## 5. Brute-Force Rate Limiting & User Enumeration Prevention

- **Rate Limit Window:** 15 minutes.
- **Maximum Failed Attempts:** 5 attempts per IP and per account email.
- **Lockout Action:** Subsequent login attempts within the lockout period are rejected with HTTP 429 (`TOO_MANY_ATTEMPTS`).
- **Generic Error Responses:** All failed login attempts return the identical response message: `"Invalid email or password. Please try again."` regardless of whether the email exists in the registry.

---

## 6. Role-Based Access Control (RBAC) & Tenant Isolation

Every session maps to an authenticated user profile with an immutable, server-derived role:

| Role | Operational Scope |
|:---|:---|
| **`ADMIN`** | Complete system governance: User management, role assignments, system settings, manual lab approvals, endpoint agent revocation, secret configuration, report publication, and full audit logs. |
| **`SECURITY_ANALYST`** | Defensive security operations: Target registration (subject to verification), executing website and network scans, finding assignment, status triage, retest verification, and generating report drafts. |
| **`VIEWER`** | Read-only inspection: Reviewing approved reports, dashboards, findings, and assessment metrics. All state-changing and admin endpoints are blocked. |

All records (targets, assessments, findings, reports, audit events) contain an `organization_id` property enforcing tenant boundary isolation.
