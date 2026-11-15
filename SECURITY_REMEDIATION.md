# MYX AI (Windows Edition) — Security Remediation & Hardening Guide

**Application:** MYX AI by Midhun Krishnan  
**Classification:** DEFENSIVE CYBERSECURITY ARCHITECTURE & REMEDIATION  
**Remediation Date:** November 15, 2026  
**Repository:** `https://github.com/midhunkrishnan-131/myx-ai-windows.git`  
**Backup Branch Created:** `backup-pre-hardening-20261115`  

---

## 1. Technical Remediation Actions

### C-01: Elimination of Hardcoded Administrator Credentials
- **Root Cause:** A hardcoded default password (`Midhun@1234`) was configured in `server.ts` and `init_db.py`, combined with explicit string bypasses in login handlers.
- **Remediation Implemented:**
  1. Removed `cleanPassword === 'Midhun@1234'` bypass from `server.ts`.
  2. Implemented a one-time cryptographic bootstrap routine `bootstrapAdminAccountIfNeeded()`.
  3. If `ADMIN_BOOTSTRAP_PASSWORD` is supplied in the environment, it initializes the admin account using that secret.
  4. If absent, it generates a high-entropy 20-character base64url one-time password and logs it to console on first run, permanently disabling future bootstrap creation.
  5. Updated `backend/app/database/init_db.py` to mirror this behavior with scrypt password hashing.

### C-02: User Database Isolation & Source Control Cleansing
- **Root Cause:** User records and test databases were committed to tracked files.
- **Remediation Implemented:**
  1. Staged cached deletion: `git rm --cached backend/registered_users.json backend/myx_local_test.db`.
  2. Deleted `backend/registered_users.json` from the repository filesystem.
  3. Created an isolated, git-ignored runtime storage directory `backend/runtime/` with runtime user persistence in `backend/runtime/users.json`.
  4. Updated `.gitignore` to block all `.db`, `.sqlite*`, `backend/runtime/`, `registered_users.json`, `runtime_users.json`, `*.pem`, `*.key`, and reports.

### C-03: Real Server-Side Session Architecture
- **Root Cause:** Trust in client-side state without server-side validation.
- **Remediation Implemented:**
  1. Developed in-memory server session store `activeSessions` with SHA-256 token hashing (`tokenHash = sha256(rawToken)`). Plaintext session tokens are never stored at rest.
  2. Configured session lifespan: 24-hour maximum TTL (`SESSION_TTL_MS`) and 2-hour sliding idle timeout (`SESSION_IDLE_TIMEOUT_MS`).
  3. Session issued via `Set-Cookie: myx_session=<token>; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400`.
  4. Created `requireAuth` middleware in `server.ts` that extracts the session token from cookies or `Authorization: Bearer <token>`, validates expiration, ensures account active status, and binds `req.user` and `req.session`.
  5. Implemented `POST /api/v1/auth/logout` to destroy the session server-side and clear the cookie.

### C-04: Comprehensive Endpoint Authorization & RBAC
- **Root Cause:** Unprotected backend API routes allowing unauthorized callers to perform state-changing operations.
- **Remediation Implemented:**
  1. Created `requireRole(allowedRoles)` middleware enforcing strict role boundaries (`ADMIN`, `SECURITY_ANALYST`, `VIEWER`).
  2. Attached `requireAuth` to all private query endpoints (`/settings`, `/targets`, `/assessments/history`, `/assessments/compare`, `/assessments/:id/pdf`).
  3. Restricted destructive or elevated operations (`DELETE /targets/:id`, `PATCH /settings`, `POST /reports/:id/approve`, `POST /windows-agent/:id/revoke`, `PATCH /admin/users/:id/role`, `GET /export/project-zip*`) to `ADMIN` only.
  4. Authorized assessment and finding management for `ADMIN` and `SECURITY_ANALYST`.
  5. Returns HTTP 401 for unauthenticated requests and HTTP 403 for unauthorized requests.

### C-05: Hardening of `/api/v1/bootstrap`
- **Root Cause:** Unauthenticated exposure of tenant configuration and user directory.
- **Remediation Implemented:**
  1. Gated `GET /api/v1/bootstrap` behind `requireAuth`.
  2. Masked all integration keys (`••••••••`).
  3. Stripped password hashes, salts, and recovery tokens from `orgUsers`.
  4. Scoped audit log exposure by caller role (Admins see complete logs; Analysts see scoped logs; Viewers receive empty arrays).

### H-01: Removal of Client-Side Role Forgery & Bypass Buttons
- **Root Cause:** Development shortcuts exposed in production frontend UI.
- **Remediation Implemented:**
  1. Deleted the "Admin Shortcut" bypass button and `handleDirectAdminLogin` from `src/pages/auth/AuthPortalPage.tsx`.
  2. Replaced the interactive `<select>` role switcher in `src/components/layout/TopBar.tsx` with a verified server-derived read-only role badge.
  3. Disabled `switchRoleForDemo` in `src/context/AuthContext.tsx` to ensure permissions originate solely from the authenticated backend session.

### H-02: Password Hardening, scrypt Upgrade & Rate Limiting
- **Root Cause:** Plaintext fallbacks, user enumeration, and lack of brute-force protection.
- **Remediation Implemented:**
  1. Upgraded password hashing to `scrypt` ($N=32768, r=8, p=1$, 32-byte salt).
  2. Enforced password complexity: minimum 10 characters, at least 1 uppercase, 1 lowercase, 1 digit, and 1 special symbol.
  3. Implemented `checkLoginRateLimit` and `recordLoginFailure`: maximum 5 attempts per IP and per account, enforcing a 15-minute lockout upon violation.
  4. Standardized all login errors to generic messages ("Invalid email or password") to eliminate username enumeration.

### H-03: Session-Bound CSRF Protection
- **Root Cause:** Hardcoded static token never validated on state-changing requests.
- **Remediation Implemented:**
  1. Every new session generates an unpredictable 32-byte cryptographically secure `csrfToken`.
  2. Implemented `requireCsrf` middleware checking `X-CSRF-Token` on state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`).
  3. Token validated using timing-safe comparison (`crypto.timingSafeEqual`).
  4. Automatically injected into `apiClient.ts` and `AuthContext.tsx`.

### H-04: Strict Origin Allowlist CORS
- **Root Cause:** Arbitrary origin reflection with credentials enabled.
- **Remediation Implemented:**
  1. Replaced reflection logic with a strict `Set` of approved origins (`http://localhost:3000`, `http://127.0.0.1:3000`, `http://localhost:5173`, `http://127.0.0.1:5173`, or `CORS_ALLOWED_ORIGINS`).
  2. Untrusted origins are rejected without `Access-Control-Allow-Origin` headers.
  3. Configured `Vary: Origin` header to prevent intermediate proxy cache poisoning.

### H-05: Server-Derived Audit Logging
- **Root Cause:** Audit logs trusting `req.body.actorEmail`.
- **Remediation Implemented:**
  1. Refactored all backend audit logging calls to extract identity directly from `(req as any).user.email` and `(req as any).user.role`.
  2. Disallowed caller-supplied identity spoofing across all modules.

### H-06: Genuine Target Verification & SSRF Defense Guard
- **Root Cause:** Automatic verification without proof of domain ownership.
- **Remediation Implemented:**
  1. Replaced auto-verification on `POST /api/v1/targets/:id/verify` with real DNS TXT lookup (`dns.resolveTxt`) and HTTP challenge checks (`http://<host>/.well-known/myx-challenge.txt`).
  2. Manual approval (`ADMIN_LAB_APPROVAL`) restricted exclusively to administrators.
  3. SSRF guard strictly blocks loopbacks (`127.0.0.1`, `localhost`), link-local metadata (`169.254.169.254`), non-HTTP schemes (`file://`, `gopher://`), and RFC 1918 private subnets without explicit administrator lab authorization.

---

## 2. Git History Cleanup Procedure (For User Execution)

> [!WARNING]
> **IMPORTANT:** Per security requirements, the Git history cleanup commands below will rewrite past commits to purge sensitive user files (`backend/registered_users.json` and `backend/myx_local_test.db`).
> **Do NOT run this if other collaborators are actively working on the same branch without coordination.**
> A full local backup branch `backup-pre-hardening-20261115` has already been created.

### Step-by-Step History Scrubbing Procedure:

#### Option A: Using `git-filter-repo` (Recommended by Git)
```bash
# 1. Install git-filter-repo via pip if not installed
python -m pip install git-filter-repo

# 2. Run filter-repo to permanently expunge sensitive files across all commits
git filter-repo --invert-paths --path backend/registered_users.json --path backend/myx_local_test.db --force

# 3. Verify clean status
git log --all --full-history -- "**/registered_users.json"
# (Output should be empty)

# 4. Once verified and approved, force push to your remote repository
# git push origin main --force --tags
```

#### Option B: Using BFG Repo-Cleaner
```bash
# 1. Download bfg.jar
# 2. Run BFG to delete sensitive files
java -jar bfg.jar --delete-files registered_users.json
java -jar bfg.jar --delete-files myx_local_test.db

# 3. Clean git reflog
git reflog expire --expire=now --all && git gc --prune=now --aggressive

# 4. Once verified and approved, push to remote:
# git push origin main --force
```
