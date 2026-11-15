# MYX AI (Windows Edition) — Production Deployment Security Checklist

**Application:** MYX AI by Midhun Krishnan  
**Classification:** DEVSECOPS & PRODUCTION HARDENING MANUAL  
**Target Environment:** Windows 10/11, Windows Server 2022, or Linux Container Deployment  
**Revision:** 2.4.0-SEC  
**Date:** November 15, 2026  

---

## 1. Environment Variable Configuration

Prior to initiating production deployment, ensure the following environment variables are set in a secure secret manager (e.g., Azure Key Vault, AWS Secrets Manager, or HashiCorp Vault) or inside an untracked, permissions-restricted `.env` file ($0600$ permissions):

| Variable | Description | Security Requirement | Example / Default |
|:---|:---|:---|:---|
| `ADMIN_BOOTSTRAP_PASSWORD` | Initial one-time administrator password. | Minimum 16 high-entropy alphanumeric/symbol characters. If unset, a 20-character secret is generated on first startup and logged once. | `Pr0d#Admin_MYX!2026` |
| `SECRET_KEY` | HMAC signing key for agent tokens and internal cryptographic operations. | 64-character hexadecimal or base64 string ($256$ bits entropy). | Generate via `openssl rand -hex 32` |
| `CORS_ALLOWED_ORIGINS` | Comma-separated list of approved web origins. | **Strict explicit allowlist only.** Never use `*` with credentials. | `https://myx-security.io,https://app.myx-security.io` |
| `DATABASE_URL` | Authoritative PostgreSQL or SQLite storage connection string. | Use authenticated TLS connection string (`sslmode=require`). | `postgresql://myx_user:Pass@db.internal:5432/myx_prod?sslmode=require` |
| `GEMINI_API_KEY` | Primary Google Gemini LLM API key. | Rotated quarterly; restricted to Gemini generative API in GCP IAM. | `AIzaSy...` |
| `GEMINI_API_KEY_2` | Backup Google Gemini API key for high-availability failover. | Resides in separate billing quota or secondary project. | `AIzaSy...` |
| `GROQ_API_KEY` | Secondary failover LLM provider key (`openai/gpt-oss-120b`). | Write-only stored; restricted to inference endpoints. | `gsk_...` |
| `VIRUSTOTAL_API_KEY` | Threat intelligence feed enrichment key. | Enterprise or community API key. | `f7f84...` |

---

## 2. HTTPS & Transport Layer Security (TLS)

1. **Enforce TLS 1.2 and 1.3:** Disable legacy protocols (`SSLv3`, `TLS 1.0`, `TLS 1.1`) and weak ciphers (RC4, 3DES, CBC suites).
2. **HTTP Strict Transport Security (HSTS):**
   Deploy on the reverse proxy (Nginx / Caddy / Cloudflare / IIS):
   ```http
   Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
   ```
3. **Automated Certificate Renewal:** Configure automated certificate issuance via Let's Encrypt / Certbot or an internal PKI with 60-day renewal thresholds.

---

## 3. Mandatory HTTP Security Headers

Ensure the reverse proxy or application runtime injects the following response headers across all routes:

```http
# Prevent clickjacking / frame embedding
X-Frame-Options: SAMEORIGIN

# Prevent MIME-sniffing
X-Content-Type-Options: nosniff

# Restrict referrer disclosure
Referrer-Policy: strict-origin-when-cross-origin

# Enforce Permissions-Policy
Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()

# Content-Security-Policy (CSP)
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self' https://generativelanguage.googleapis.com https://api.groq.com; frame-ancestors 'self';
```

---

## 4. Production Cookie Hardening

For production HTTPS environments, ensure the `myx_session` cookie attributes match:

```http
Set-Cookie: myx_session=<session_token>; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400
```
- `HttpOnly`: **Mandatory** — blocks access from JavaScript (`document.cookie`).
- `Secure`: **Mandatory** in HTTPS — prevents transmission over unencrypted HTTP.
- `SameSite=Lax`: **Mandatory** — mitigates CSRF while allowing legitimate top-level navigations.

---

## 5. Reverse Proxy Architecture & Rate Limiting

Deploy a reverse proxy (e.g., Nginx, Envoy, or Cloudflare) in front of the Node.js/Vite (`:3000`) and FastAPI (`:8000`) services.

### Nginx Sample Hardening Block:
```nginx
# Rate limiting zone for auth endpoints: 5 requests per minute per IP
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=5r/m;

# Limit request body sizes to 5MB to prevent memory exhaustion
client_max_body_size 5M;

# Gating authentication endpoints
location /api/v1/auth/ {
    limit_req zone=auth_limit burst=3 nodelay;
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

# Proxy pass for internal FastAPI assessments
location /api/v1/assessments/ {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

---

## 6. SSRF & Egress Firewall Rules

Because MYX AI conducts active network and website security assessments, strict outbound egress controls must be enforced:
1. **Cloud Metadata Isolation:** At the OS / VPC firewall layer, block all outbound connections to `169.254.169.254` from the application worker processes:
   ```bash
   # Linux iptables example
   iptables -A OUTPUT -m owner --uid-owner myxapp -d 169.254.169.254 -j DROP
   ```
2. **Private Network Filtering:** Ensure the `SafeOutboundHttpClient` and `validateTargetSsrfGuard` filters are enabled to disallow scanning internal RFC 1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) unless explicitly overridden in administrative lab mode.

---

## 7. Incident Response, Key Rotation & Audit Log Archival

1. **Immediate Credential Rotation on Suspected Breach:**
   - Terminate all active sessions by restarting or invoking `activeSessions.clear()`.
   - Rotate `SECRET_KEY`, `ADMIN_BOOTSTRAP_PASSWORD`, and external API keys (`GEMINI_API_KEY`, `VIRUSTOTAL_API_KEY`).
2. **Immutable Audit Log Archival:**
   - Configure a cron or scheduled background task to flush entries from `dbState.auditLogs` into a write-once, append-only log aggregator (e.g., Elasticsearch, Splunk, or AWS CloudWatch Logs).
   - Audit entries record `actor_email`, `actor_role`, `ip_address`, `event_category`, `action`, and timestamps for forensics.
3. **Database Backup & Recovery:**
   - Perform automated daily snapshots of SQLite / PostgreSQL databases with AES-256 encryption at rest.
   - Test snapshot restoration quarterly in an isolated staging environment.
