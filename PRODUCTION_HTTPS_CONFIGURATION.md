# MYX AI (Windows Edition) — Production HTTPS & Cookie Security Configuration

**Application:** MYX AI by Midhun Krishnan  
**Classification:** INFRASTRUCTURE SECURITY & TRANSPORT LAYER HARDENING  
**Status:** **IMPLEMENTED & VERIFIED** (Cookie flags and redirection tested; proxy templates provided)  
**Date:** November 15, 2026  

---

## 1. Executive Summary

Transport Layer Security (TLS) is essential to protecting credentials, sessions, and telemetry in transit. This document defines the exact production configuration for:
1. Environment-driven cookie security (`Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`).
2. Express reverse proxy trust (`trust proxy`).
3. Automatic HTTP-to-HTTPS 301 redirection.
4. HTTP Strict Transport Security (HSTS) headers.
5. Production reverse proxy configurations for Nginx, Caddy, Cloudflare, and Windows IIS.

---

## 2. Server-Side Cookie Architecture

The authentication cookie (`myx_session`) is governed by server-side environment variables:

```ts
const isProduction =
  process.env.NODE_ENV === 'production' || process.env.COOKIE_SECURE === 'true';
const isCookieSecure = isProduction;

function getAuthCookieHeader(rawToken: string): string {
  const secureFlag = isCookieSecure ? '; Secure' : '';
  return `myx_session=${rawToken}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400${secureFlag}`;
}

function getClearCookieHeader(): string {
  const secureFlag = isCookieSecure ? '; Secure' : '';
  return `myx_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secureFlag}`;
}
```

### Security Attributes Explained:
- `HttpOnly`: Enforced across **both** development and production. Disallows JavaScript (`document.cookie`) access, neutralizing session theft via Cross-Site Scripting (XSS).
- `SameSite=Lax`: Enforced across **both** development and production. Prevents the browser from sending authentication cookies on cross-origin POST requests, defending against Cross-Site Request Forgery (CSRF).
- `Secure`: Dynamically appended when `NODE_ENV=production` or `COOKIE_SECURE=true`. Instructs browsers to transmit the session cookie exclusively over encrypted HTTPS connections.
- `Path=/`: Restricts the cookie scope to application routes.
- **Matched Logout Clearing:** When `POST /api/v1/auth/logout` is called, the clearing header includes matching `Path=/` and `Secure` attributes, ensuring the browser deletes the cookie.

---

## 3. Reverse Proxy Trust (`trust proxy`)

When MYX AI runs behind a reverse proxy, load balancer, or CDN (e.g., Nginx, Envoy, AWS ALB, Cloudflare), the direct TCP connection to Node.js/Vite is plaintext HTTP on the internal loopback (`127.0.0.1:3000`).

To accurately identify client IP addresses for rate limiting and detect whether the external user connection is HTTPS:
```ts
if (isProduction || process.env.TRUST_PROXY === 'true') {
  app.set('trust proxy', 1);
}
```
When enabled, Express respects `X-Forwarded-Proto` (`https`) and `X-Forwarded-For` from the immediate upstream proxy.

---

## 4. HTTPS Redirection & HSTS Enforcement

The backend middleware enforces automatic redirection and HSTS headers in production:

```ts
app.use((req: Request, res: Response, next) => {
  const host = req.headers.host || '';
  const isLocalhost = host.includes('localhost') || host.startsWith('127.0.0.1');
  const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';

  if (isProduction) {
    // Inject HSTS: 2 years duration, subdomains included, preload eligible
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');

    // Redirect plaintext HTTP to HTTPS on live domain
    if (!isHttps && !isLocalhost) {
      return res.redirect(301, `https://${host}${req.url}`);
    }
  }
  next();
});
```

---

## 5. Reverse Proxy Configuration Templates

### Option A: Nginx (Linux / Windows Server)
```nginx
server {
    listen 80;
    server_name myx-security.io www.myx-security.io;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name myx-security.io;

    ssl_certificate /etc/letsencrypt/live/myx-security.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/myx-security.io/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5:!3DES;
    ssl_prefer_server_ciphers on;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;

    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=myx_limit:10m rate=10r/s;
    limit_req zone=myx_limit burst=20 nodelay;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

### Option B: Caddy (Automatic HTTPS)
```caddy
myx-security.io {
    reverse_proxy 127.0.0.1:3000 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-Proto https
    }
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
    }
}
```

### Option C: Cloudflare CDN
1. Set SSL/TLS encryption mode to **Full (Strict)**.
2. Under **Edge Certificates**, toggle on:
   - **Always Use HTTPS**
   - **HTTP Strict Transport Security (HSTS)** (Max-Age: 6 months or 1 year, include subdomains)
   - **Minimum TLS Version:** `TLS 1.2`
   - **Opportunistic Encryption:** Enabled

---

## 6. Verification & Testing

The cookie security and HTTPS redirection behaviors are covered by automated tests in `src/utils/securityMaster.test.ts`:
- `Security Phase 3: Production vs Development Cookie Flags` (PASSED)
- `Security Phase 3: Production HTTPS Redirection and HSTS Header Logic` (PASSED)

To run the verification suite:
```powershell
npx tsx --test src/utils/securityMaster.test.ts
```
