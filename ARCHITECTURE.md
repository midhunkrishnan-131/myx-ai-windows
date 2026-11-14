# SYSTEM ARCHITECTURE — MYX AI (WINDOWS EDITION)

**Brand:** MYX AI by Midhun Krishnan ("Discover. Detect. Defend.")

---

## 1. High-Level Architecture Diagram

```mermaid
flowchart TB
    subgraph Client["Cross-Platform Browser (Desktop, Tablet, Mobile)"]
        UI["React 19 + TypeScript UI (17 Views)"]
        APIClient["Centralized apiClient.ts (HttpOnly Cookie + X-CSRF-Token)"]
        UI --> APIClient
    end

    subgraph WinHost["Authorized Windows 10 / 11 Endpoint"]
        WinAgent["MYX-Windows-Agent (Read-Only Collectors)"]
        PS["PowerShell / WMI / Defender / BitLocker / netsh wlan"]
        WinAgent --> PS
    end

    subgraph Backend["FastAPI Backend (/api/v1/*)"]
        Auth["Argon2id + Stateful Session + RFC 6238 TOTP Replay Guard"]
        RBAC["RBAC Enforcement (ADMIN, SECURITY_ANALYST, VIEWER)"]
        SSRF["SafeOutboundHttpClient (DNS Resolution + IP Pinning + 169.254.169.254 Block)"]
        Parsers["DefusedXML Scanner Parsers (Burp, ZAP, Nmap, Nessus, Nikto)"]
        GeminiRouter["Gemini Model Router (google-genai SDK)"]
        RAG["Tenant-Isolated pgvector Retriever (<untrusted_reference_context>)"]
    end

    subgraph Persistence["PostgreSQL 15+ (Neon / Supabase / Local)"]
        DB[("31 Normalized SQLAlchemy 2.0 Tables")]
        Vec[("rag_document_chunks Vector(768)")]
    end

    APIClient -->|HTTPS + CSRF| Auth
    WinAgent -->|Bearer Token + HMAC-SHA256| Backend
    Auth --> RBAC
    RBAC --> SSRF
    RBAC --> Parsers
    RBAC --> GeminiRouter
    GeminiRouter --> RAG
    RAG --> Vec
    Backend --> DB
```

---

## 2. Outbound SSRF & DNS Rebinding Protection Flow

1. **Scheme Validation:** Only `http://` and `https://` are allowed. `file://`, `gopher://`, `ftp://`, `dict://`, and `ldap://` are immediately rejected.
2. **Allowlist Verification:** Every Website, Network, SSL/TLS, or DNS assessment verifies that the target exists in `authorized_targets` with `verification_status == 'VERIFIED'`.
3. **DNS Resolution & IP Blocklist Validation:** Before opening a socket, `validate_and_resolve_target_url` resolves all `A`/`AAAA` records and checks every IP against:
   - Loopback (`127.0.0.0/8`, `::1/128`, `localhost`) — Unconditionally blocked.
   - Link-Local & Cloud Metadata (`169.254.0.0/16`, `169.254.169.254`, `fe80::/10`) — Unconditionally blocked in all modes.
   - RFC 1918 Private Ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) — Blocked unless `ALLOW_CONTROLLED_LAB_TARGETS=true` AND an `ADMIN` approved the target.
4. **Manual Redirect Validation:** Follows at most 5 redirects manually, re-running full DNS and IP validation on every `Location` header hop.
