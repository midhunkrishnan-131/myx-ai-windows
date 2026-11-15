# MYX AI (Windows Edition) — Credential & API Key Rotation Guide

**Application:** MYX AI by Midhun Krishnan  
**Classification:** IDENTITY & ACCESS MANAGEMENT / KEY ROTATION PROCEDURES  
**Status:** **IMPLEMENTED & VERIFIED** (Rotation endpoints live; manual provider actions documented)  
**Date:** November 15, 2026  

---

## 1. Executive Summary

Because credentials and provider API keys were previously used during local testing and development, defense-in-depth principles require treating all pre-remediation credentials as potentially compromised.

This guide provides:
1. Operational procedures for rotating user and administrator passwords via backend API endpoints.
2. Invalidation of sessions across all devices upon credential rotation.
3. Step-by-step instructions for regenerating and rotating external API keys (Google Gemini, Groq, VirusTotal, Google Safe Browsing, Resend) without exposing secret values.

---

## 2. Administrator & User Password Rotation

### Option A: Self-Service Password Rotation (Authenticated)
Any authenticated user or administrator can rotate their account password directly.

**Endpoint:** `POST /api/v1/auth/rotate-password`  
**Headers:**
- `Content-Type: application/json`
- `Cookie: myx_session=<session_token>`
- `X-CSRF-Token: <session_csrf_token>`

**Request Body:**
```json
{
  "currentPassword": "<Current_Account_Password>",
  "newPassword": "<New_High_Entropy_Password>"
}
```

**Security Enforcements:**
1. Validates `currentPassword` against stored `scrypt` hash.
2. Enforces password complexity rules on `newPassword` ($\ge 10$ chars, uppercase, lowercase, digit, symbol).
3. Rejects identical passwords (`newPassword !== currentPassword`).
4. Generates a fresh 32-byte salt and derives a new `scrypt` hash ($N=32768, r=8, p=1$).
5. **Immediately revokes all existing sessions** across all devices for this account.
6. Issues a new single session cookie and CSRF token to the rotating client.
7. Logs an immutable audit event (`PASSWORD_ROTATED_SUCCESS`).

### Option B: Account Recovery / Reset Flow (Unauthenticated)
For locked or forgotten accounts, a single-use, time-limited token flow is implemented:

1. **Request Reset Token:**
   - **Endpoint:** `POST /api/v1/auth/forgot-password`
   - **Body:** `{"email": "midhun.krishnan@myx-security.io"}`
   - **Protection:** Rate-limited to 5 requests per 15 minutes. Returns generic success to prevent account enumeration.
2. **Execute Password Reset:**
   - **Endpoint:** `POST /api/v1/auth/reset-password`
   - **Body:**
     ```json
     {
       "token": "<32_byte_hex_token>",
       "newPassword": "<New_Strong_Password_10+>"
     }
     ```
   - **Protection:** Token is hashed with SHA-256 at rest, valid for 1 hour, single-use only. Upon execution, all existing sessions for the target user are permanently terminated.

---

## 3. External API Key Rotation Procedures

MYX AI interfaces with external security intelligence and AI providers. Follow the steps below to regenerate and deploy fresh keys:

### 1. Google Gemini API Key Rotation
- **Used by:** AI Security Analyst, Copilot Briefings, Remediation Generator
- **Portal:** [Google AI Studio — API Keys](https://aistudio.google.com/app/apikey)
- **Rotation Steps:**
  1. Sign in to Google AI Studio.
  2. Locate your existing project and click **Create API Key** in a new or existing Cloud Project.
  3. Copy the newly generated key (`AIzaSy...`).
  4. Delete or disable the previous API key in Google Cloud Console Credentials.
  5. In `myx-ai/.env` (and `backend/.env`), update:
     ```bash
     GEMINI_API_KEY="<new_primary_key>"
     GEMINI_API_KEY_2="<optional_backup_key_in_secondary_project>"
     ```

### 2. Groq AI Failover Key Rotation
- **Used by:** Secondary multi-cloud failover inference (`openai/gpt-oss-120b`)
- **Portal:** [Groq Console — API Keys](https://console.groq.com/keys)
- **Rotation Steps:**
  1. Open Groq Console and navigate to **API Keys**.
  2. Click **Create API Key**, name it `MYX-AI-Prod-Failover`.
  3. Revoke the previous key.
  4. In `myx-ai/.env` (and `backend/.env`), update:
     ```bash
     GROQ_API_KEY="<new_groq_key>"
     ```

### 3. VirusTotal v3 Key Rotation
- **Used by:** LinkGuard Multi-Vendor Threat Intelligence Enrichment
- **Portal:** [VirusTotal User Profile — API Key](https://www.virustotal.com/gui/user/<username>/apikey)
- **Rotation Steps:**
  1. Log in to VirusTotal and select **API Key** from your profile menu.
  2. Click **Regenerate key**.
  3. In `myx-ai/.env` (and `backend/.env`), update:
     ```bash
     VIRUSTOTAL_API_KEY="<new_virustotal_key>"
     ```
  4. In the MYX AI web portal, navigate to **Integrations -> VirusTotal v3** and supply the new key via the write-only configuration modal.

### 4. Google Safe Browsing v4 Key Rotation
- **Used by:** LinkGuard URL reputation lookup
- **Portal:** [Google Cloud Console — Credentials](https://console.cloud.google.com/apis/credentials)
- **Rotation Steps:**
  1. Navigate to Google Cloud Console -> APIs & Services -> Credentials.
  2. Select your Web API key restricted to "Safe Browsing API".
  3. Click **Regenerate Key**.
  4. In `myx-ai/.env` (and `backend/.env`), update:
     ```bash
     GOOGLE_SAFE_BROWSING_API_KEY="<new_gsb_key>"
     ```

---

## 4. Secret Storage Best Practices

1. **Never Commit Secrets:** The `.env` file must remain in `.gitignore`. Only `.env.example` with blank/placeholder values is committed.
2. **Write-Only Storage in Web UI:** When external API keys are entered via the **Integrations** page (`POST /api/v1/integrations/:provider/secret`), the backend returns only the last 4 characters (`••••••••8F2A`). The raw key is never returned in JSON payloads.
3. **Environment Segregation:** Use separate API keys for local staging/development and production.
