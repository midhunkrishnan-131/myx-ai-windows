# FRONTEND-TO-BACKEND REST API CONTRACT (`API_INTEGRATION.md`)

**Base URL:** `import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000"`  
**Version Prefix:** `/api/v1`  
**Session & CSRF Contract:** All requests include `credentials: "include"` (`myx_session` `HttpOnly; SameSite=Lax` cookie). All state-changing `POST`, `PUT`, `PATCH`, and `DELETE` requests include `X-CSRF-Token`.

---

## Complete Service-to-Endpoint Mapping (24 Domains)

| Frontend Service (`src/services/*.ts`) | Method | FastAPI Endpoint (`/api/v1/*`) | Required RBAC Roles | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `apiClient.checkBackendHealth()` | `GET` | `/api/v1/health` | Public | Verifies FastAPI reachability & brand metadata |
| `authService.getCurrentUser()` | `GET` | `/api/v1/auth/me` | `ADMIN`, `ANALYST`, `VIEWER` | Returns current authenticated user profile |
| `authService.getSessions()` | `GET` | `/api/v1/auth/sessions` | `ADMIN`, `ANALYST`, `VIEWER` | Lists active stateful sessions in `user_sessions` |
| `authService.initiateTotpSetup()` | `POST` | `/api/v1/auth/2fa/setup` | `ADMIN`, `ANALYST`, `VIEWER` | Generates encrypted 160-bit Base32 secret & QR SVG |
| `authService.confirmTotpSetup()` | `POST` | `/api/v1/auth/2fa/confirm` | `ADMIN`, `ANALYST`, `VIEWER` | Verifies 6-digit TOTP code & issues 10 recovery codes |
| `targetsService.listTargets()` | `GET` | `/api/v1/targets` | `ADMIN`, `ANALYST`, `VIEWER` | Lists organization's `authorized_targets` |
| `targetsService.verifyTargetOwnership()` | `POST` | `/api/v1/targets/{id}/verify` | `ADMIN`, `ANALYST` | Verifies DNS TXT, HTTP `.well-known`, or Lab Approval |
| `assessmentsService.listAssessments()` | `GET` | `/api/v1/assessments` | `ADMIN`, `ANALYST`, `VIEWER` | Lists unified assessment history & posture scores |
| `assessmentsService.runWebsiteAssessment()` | `POST` | `/api/v1/assessments/website/run` | `ADMIN`, `ANALYST` | Runs non-destructive HTTP header, cookie & redirect check |
| `assessmentsService.runNetworkAssessment()` | `POST` | `/api/v1/assessments/network/run` | `ADMIN`, `ANALYST` | Runs bounded allowlisted TCP service discovery |
| `windowsAgentService.listAgents()` | `GET` | `/api/v1/windows/agents` | `ADMIN`, `ANALYST`, `VIEWER` | Lists enrolled Windows 10/11 agents & privilege levels |
| `windowsAgentService.generateEnrollmentToken()` | `POST` | `/api/v1/windows/agents/enroll-token` | `ADMIN`, `ANALYST` | Issues single-use 15-minute `MYX-ENR-...` token |
| `windowsAgentService.revokeAgent()` | `POST` | `/api/v1/windows/agents/{id}/revoke` | `ADMIN`, `ANALYST` | Immediately revokes Windows agent token & HMAC secret |
| `windowsAgentService.getWifiAuditRuns()` | `GET` | `/api/v1/auditors/wifi/runs` | `ADMIN`, `ANALYST`, `VIEWER` | Returns defensive Windows `netsh wlan` BSSID audit runs |
| `linkguardService.analyzeUrl()` | `POST` | `/api/v1/intelligence/linkguard/analyze` | `ADMIN`, `ANALYST`, `VIEWER` | Lexical/Punycode check, SSRF redirect trace & TI lookup |
| `analyzersService.analyzeSslTls()` | `POST` | `/api/v1/analyzers/ssl-tls/run` | `ADMIN`, `ANALYST`, `VIEWER` | X.509 certificate chain & TLS 1.0–1.3 protocol matrix |
| `analyzersService.analyzeDns()` | `POST` | `/api/v1/analyzers/dns/run` | `ADMIN`, `ANALYST`, `VIEWER` | DNS resolution + SPF 10-lookup, DMARC & DNSSEC checks |
| `findingsService.listFindings()` | `GET` | `/api/v1/findings` | `ADMIN`, `ANALYST`, `VIEWER` | Lists findings with CVSS v3.1, CVE/CWE, & evidence |
| `findingsService.updateFindingStatus()` | `POST` | `/api/v1/findings/{id}/status` | `ADMIN`, `ANALYST` | Updates status & appends immutable finding audit log |
| `aiService.listSessions()` | `GET` | `/api/v1/ai/chat/sessions` | `ADMIN`, `ANALYST` | Lists AI Security Analyst sessions & citations |
| `aiService.listRagDocuments()` | `GET` | `/api/v1/rag/documents` | `ADMIN`, `ANALYST` | Lists global & tenant-scoped RAG reference documents |
| `reportsService.listReports()` | `GET` | `/api/v1/reports` | `ADMIN`, `ANALYST`, `VIEWER` | Lists Draft, In-Review, and Approved security reports |
| `reportsService.listImports()` | `GET` | `/api/v1/imports` | `ADMIN`, `ANALYST` | Lists `defusedxml`-validated Burp/ZAP/Nmap/Nessus imports |
| `integrationsService.listIntegrations()` | `GET` | `/api/v1/integrations` | `ADMIN`, `ANALYST` | Returns masked status of Gemini, Postgres, Resend, TI |
| `integrationsService.testConnectivity()` | `POST` | `/api/v1/integrations/{provider}/test` | `ADMIN` | Executes live connectivity check for external provider |
| `adminService.listUsers()` | `GET` | `/api/v1/users` | `ADMIN` | Lists organization members, roles & 2FA enrollment |
| `adminService.listAuditLogs()` | `GET` | `/api/v1/audit-logs` | `ADMIN` | Queries append-only `audit_logs` ledger |
