# MYX AI (Windows Edition) — Production Deployment Checklist

**Application:** MYX AI by Midhun Krishnan  
**Tagline:** Discover. Detect. Defend.  
**Classification:** DEVSECOPS & GO-LIVE VERIFICATION CHECKLIST  
**Status:** **READY FOR DEPLOYMENT**  
**Date:** November 15, 2026  

---

## 1. Pre-Deployment Configuration & Secret Vaulting

- [x] **No Secrets in Source:** Confirmed `.env` and runtime databases are excluded from Git via `.gitignore`.
- [x] **Safe Example Template:** Verified `.env.example` contains only placeholder values.
- [ ] **Production Secrets Provisioned:** Set high-entropy production environment variables:
  - `ADMIN_BOOTSTRAP_PASSWORD` (minimum 16 chars)
  - `SECRET_KEY` (64-char hex via `openssl rand -hex 32`)
  - `GEMINI_API_KEY` (Google AI Studio production key)
  - `VIRUSTOTAL_API_KEY` (VirusTotal production key)
  - `DATABASE_URL` (PostgreSQL connection string with `sslmode=require`)
- [x] **Strict CORS Origins:** Configure `CORS_ALLOWED_ORIGINS` to list exact domain names only (e.g. `https://myx-security.io`).

---

## 2. Transport Layer Security & Cookie Policies

- [x] **Environment-Driven Cookie Security:** `Secure` flag automatically appended when `NODE_ENV=production` or `COOKIE_SECURE=true`.
- [x] **Cookie Access Restricted:** `HttpOnly` and `SameSite=Lax` active on all session cookies.
- [x] **Reverse Proxy Trust:** `trust proxy` enabled when behind an upstream proxy.
- [x] **HTTPS Enforcement:** Production requests on HTTP redirect to HTTPS with HTTP 301.
- [x] **HSTS Header Injected:** `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` header active.
- [ ] **TLS Certificate Active:** Deploy valid Let's Encrypt or enterprise PKI SSL/TLS certificate on reverse proxy (TLS 1.2 / TLS 1.3 only).

---

## 3. Session Persistence & Authentication Governance

- [x] **Persistent Session Storage:** Sessions persisted to disk-backed atomic store (`backend/runtime/sessions.json`) and SQLAlchemy `UserSession` table.
- [x] **Raw Tokens Never Stored:** SHA-256 token hashing active for all stored session records.
- [x] **Sliding & Absolute Timeouts:** 24-hour absolute TTL and 2-hour sliding idle timeout enforced.
- [x] **Single-Session Logout:** `POST /api/v1/auth/logout` invalidates session and clears cookies with matching attributes.
- [x] **Global Revocation on Password Change:** Rotating passwords (`/api/v1/auth/rotate-password`) invalidates all existing sessions across all browsers.
- [x] **Immediate Revocation on Account Deactivation:** Disabling an account immediately invalidates all active sessions.

---

## 4. API Authorization & SSRF Egress Defenses

- [x] **Centralized Auth & RBAC:** Every API route validates sessions via `requireAuth` and enforces role tiering (`requireRole`).
- [x] **Session-Bound CSRF Defense:** `X-CSRF-Token` validated in constant-time on state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`).
- [x] **Server-Derived Audit Identity:** Audit logs derive `actor_email` and `actor_role` strictly from server sessions.
- [x] **DNS TXT / HTTP Target Verification:** Target ownership verified via real DNS TXT lookup or HTTP challenge file.
- [x] **SSRF Egress Defense:** Unconditional blocking of loopback (`127.0.0.1`), cloud metadata (`169.254.169.254`), non-HTTP schemes, and unapproved RFC 1918 subnets.

---

## 5. Post-Deployment Verification & Smoke Tests

After launching in production:
1. Visit `https://<domain>/api/v1/health` and verify `status: ok` and `mode: LIVE_BACKEND`.
2. Attempt login with unauthenticated user; verify generic error message and rate limiting.
3. Sign in as administrator and verify:
   - Session cookie arrives with `Secure; HttpOnly; SameSite=Lax`.
   - `X-CSRF-Token` header is present.
   - TopBar displays verified server-derived role badge.
4. Execute a live Website Assessment scan against an authorized target.
5. Verify that restarting the backend service does not log out active sessions.
