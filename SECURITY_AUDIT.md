# MYX AI (Windows Edition) — Comprehensive Security Audit Report

**Application:** MYX AI by Midhun Krishnan  
**Tagline:** Discover. Detect. Defend.  
**Auditor:** Senior Application Security & Backend Security Architecture Team  
**Audit Date:** November 15, 2026  
**Repository:** `https://github.com/midhunkrishnan-131/myx-ai-windows.git`  
**Classification:** DEFENSIVE CYBERSECURITY PLATFORM AUDIT  

---

## Executive Summary

A comprehensive application security audit and vulnerability assessment was conducted against the **MYX AI (Windows Edition)** codebase. The audit inspected both the Node.js/TypeScript backend (`server.ts`), the FastAPI backend service (`backend/app/`), client-side authentication context (`AuthContext.tsx`, `AuthPortalPage.tsx`, `TopBar.tsx`), API client abstractions (`apiClient.ts`), data persistence models, and Git version control history.

Prior to remediation, the platform contained multiple **Critical** and **High-Severity** vulnerabilities that undermined tenant boundary isolation, credential confidentiality, and endpoint authorization. These findings have been documented below alongside their remediation status.

---

## Vulnerability Summary Matrix

| ID | Title | Severity | CWE | OWASP Top 10 | Status |
|:---|:---|:---|:---|:---|:---|
| **C-01** | Hardcoded Administrator Credentials & Default Password Bypass | **Critical** | CWE-798 | A07:2021 Identification & Auth Failures | **Remediated** |
| **C-02** | Sensitive Database & User Records Tracked in Source Control | **Critical** | CWE-312 | A01:2021 Broken Access Control | **Remediated** |
| **C-03** | Missing Server-Side Session Validation & Plaintext Auth Fallbacks | **Critical** | CWE-306 | A07:2021 Identification & Auth Failures | **Remediated** |
| **C-04** | Unprotected Backend API Endpoints & Client-Side Only Route Guards | **Critical** | CWE-285 | A01:2021 Broken Access Control | **Remediated** |
| **C-05** | Sensitive Data Exposure on Public `/api/v1/bootstrap` Endpoint | **Critical** | CWE-200 | A01:2021 Broken Access Control | **Remediated** |
| **H-01** | Client-Side Role Forgery & "Admin Shortcut" Bypass Button | **High** | CWE-269 | A01:2021 Broken Access Control | **Remediated** |
| **H-02** | Weak Password Storage, Account Enumeration & Missing Rate Limiting | **High** | CWE-916 | A07:2021 Identification & Auth Failures | **Remediated** |
| **H-03** | Static Hardcoded CSRF Token & Lack of State-Changing Request Validation | **High** | CWE-352 | A01:2021 Broken Access Control | **Remediated** |
| **H-04** | Overly Permissive CORS Reflecting Arbitrary Origins with Credentials | **High** | CWE-346 | A05:2021 Security Misconfiguration | **Remediated** |
| **H-05** | Client-Supplied Actor Identity & Tamperable Audit Logs | **High** | CWE-284 | A09:2021 Security Logging Failures | **Remediated** |
| **H-06** | Automatic Target Verification & Potential SSRF Egress | **High** | CWE-918 | A10:2021 Server-Side Request Forgery | **Remediated** |

---

## Detailed Vulnerability Analysis

### C-01: Hardcoded Administrator Credentials & Default Password Bypass
- **Severity:** Critical (CVSS 9.8)
- **Affected Files:** `server.ts`, `backend/app/database/init_db.py`, `src/pages/auth/AuthPortalPage.tsx`
- **Description:** The application automatically seeded an administrator account with the hardcoded plaintext password `Midhun@1234`. Furthermore, `server.ts` contained an explicit bypass checking `cleanPassword === 'Midhun@1234'`, and `init_db.py` provisioned identical credentials on database startup.
- **Impact:** Any adversary reading public source code or decompiling the build artifact could authenticate with root administrator privileges.

### C-02: Sensitive Database & User Records Tracked in Git
- **Severity:** Critical (CVSS 9.1)
- **Affected Files:** `backend/registered_users.json`, `backend/myx_local_test.db`, `.gitignore`
- **Description:** Real user accounts, personal identity information (full names, emails), and user password hashes were committed directly into the Git repository across multiple historical commits (`2ec4d8d`, `1b0fff2`, `4a28b22`, `5421de0`, `bc6e6a5`).
- **Impact:** Cloned repositories exposed user identity records and password hashes directly.

### C-03: Missing Server-Side Session Architecture
- **Severity:** Critical (CVSS 9.4)
- **Affected Files:** `src/context/AuthContext.tsx`, `server.ts`
- **Description:** Authentication was evaluated purely within the client React layer using `localStorage`/`sessionStorage`. The `/api/v1/auth/me` endpoint returned a hardcoded admin profile unconditionally to any caller without checking session tokens.
- **Impact:** Attackers could forge authentication by manually populating browser storage keys.

### C-04: Unprotected Backend Endpoints & Missing RBAC
- **Severity:** Critical (CVSS 9.6)
- **Affected Files:** `server.ts` (all endpoints)
- **Description:** State-changing endpoints (target registration, target deletion, scans, agent revocation, integration key modifications, and role updates) lacked server-side authorization checks, relying solely on client-side React UI conditional rendering.
- **Impact:** Ordinary viewers or unauthenticated remote attackers could invoke REST endpoints directly using tools like `curl` to wipe targets, trigger scans, or change admin roles.

### C-05: Unauthenticated Data Leakage via `/api/v1/bootstrap`
- **Severity:** Critical (CVSS 8.6)
- **Affected Files:** `server.ts:668`
- **Description:** The `/api/v1/bootstrap` synchronization endpoint returned full database state—including all registered user accounts, integration configurations, and audit events—without requiring an active session.
- **Impact:** Complete exposure of organizational architecture and user directory to anonymous network callers.

### H-01: Client-Side Role Forgery & "Admin Shortcut"
- **Severity:** High (CVSS 8.8)
- **Affected Files:** `src/pages/auth/AuthPortalPage.tsx`, `src/components/layout/TopBar.tsx`
- **Description:** The login portal contained an "Admin Shortcut" button that bypassed credential submission entirely. The top navigation bar included a role `<select>` dropdown that allowed users to toggle between `ADMIN`, `SECURITY_ANALYST`, and `VIEWER` client-side.
- **Impact:** Privilege escalation from unauthenticated or low-privilege users to full platform administrator.

### H-02: Insecure Password Handling & Missing Rate Limiting
- **Severity:** High (CVSS 7.5)
- **Affected Files:** `server.ts`, `backend/app/auth/password.py`
- **Description:** Passwords lacked complexity requirements ($\ge 10$ characters with uppercase, lowercase, numbers, and symbols). Login routes returned distinct errors ("Account with this email does not exist") enabling user enumeration, and lacked brute-force rate limits.
- **Impact:** Account harvesting and dictionary attacks against portal accounts.

### H-03: Static CSRF Token
- **Severity:** High (CVSS 7.5)
- **Affected Files:** `server.ts`, `src/services/apiClient.ts`
- **Description:** CSRF protection relied on a single hardcoded string constant (`myx-csrf-live-token-2026-v24`) that was never bound to the user's session or validated on state-changing requests.
- **Impact:** Cross-Site Request Forgery vulnerability against authenticated sessions.

### H-04: Overly Permissive CORS Policy
- **Severity:** High (CVSS 7.4)
- **Affected Files:** `server.ts:616`
- **Description:** The CORS middleware reflected the incoming `Origin` header from any requesting domain while simultaneously enabling `Access-Control-Allow-Credentials: true`.
- **Impact:** Cross-origin malicious websites could make authenticated requests and read cross-origin responses.

### H-05: Client-Supplied Actor Identity in Audit Logging
- **Severity:** High (CVSS 7.1)
- **Affected Files:** `server.ts` (audit log invocations)
- **Description:** Audit events accepted `actorEmail` and `actorRole` from the caller's JSON body (`req.body.actorEmail`) rather than deriving identity strictly from the verified session.
- **Impact:** Malicious actors could forge audit trails, framing other users or hiding malicious modifications.

### H-06: Automatic Target Verification & SSRF Potential
- **Severity:** High (CVSS 8.2)
- **Affected Files:** `server.ts:814`
- **Description:** Target verification unconditionally transitioned targets from `PENDING` to `VERIFIED` upon request without executing DNS TXT record checks or HTTP challenge attestation.
- **Impact:** Attackers could register unauthorized targets or probe internal infrastructure.
