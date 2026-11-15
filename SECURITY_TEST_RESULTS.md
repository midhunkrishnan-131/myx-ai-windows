# MYX AI (Windows Edition) — Automated Security Test Results

**Application:** MYX AI by Midhun Krishnan  
**Test Date:** November 15, 2026  
**Test Environments:**  
- **Node.js:** v20.18.0 (Windows 64-bit)  
- **Python:** 3.13.9 (Windows 64-bit)  
- **Total Test Cases Executed:** 47  
- **Passed:** 47  
- **Failed:** 0  
- **Success Rate:** 100.0%  

---

## 1. Node.js TypeScript Security Master Test Suite (`securityMaster.test.ts`)

Command: `npx tsx --test src/utils/securityMaster.test.ts`  
Status: **11 / 11 PASSED (0 Failures)**

| Test Case | Category | Result | Duration | Details |
|:---|:---|:---:|:---:|:---|
| `Security C-01: No Hardcoded Administrator Passwords or Plaintext Backdoors` | Hardcoded Credentials | **PASSED** | 2.04 ms | Validated absence of `Midhun@1234` bypass string, automatic hardcoded seeding, and plaintext password fallback. |
| `Security C-02: Sensitive Database and Runtime Files Excluded from Git Tracking` | Secret Management | **PASSED** | 0.68 ms | Verified `.gitignore` blocks `backend/runtime/`, `registered_users.json`, and `.db` files; confirmed source root is clean. |
| `Security C-03 & H-02: CPU/Memory-Hard Scrypt Password Hashing with Unique 32-Byte Salts` | Cryptography | **PASSED** | 398.80 ms | Verified scrypt parameters ($N=32768, r=8, p=1$), unique salts per invocation, and mismatch rejection. |
| `Security H-02: Password Complexity Enforcement` | Account Security | **PASSED** | 0.43 ms | Verified enforcement of $\ge 10$ length, uppercase, lowercase, digit, and symbol requirements. |
| `Security C-03: Session Management with SHA-256 Token Hashing and Expiration` | Session Security | **PASSED** | 0.66 ms | Validated SHA-256 token hashing at rest, 24h TTL expiration, and 2h sliding idle timeout. |
| `Security H-03: Session-Bound CSRF Token Validation` | CSRF Defense | **PASSED** | 0.20 ms | Verified constant-time validation (`crypto.timingSafeEqual`) accepting valid tokens and rejecting forged tokens. |
| `Security C-04: Role-Based Access Control (RBAC) Enforcement Matrix` | Authorization | **PASSED** | 0.21 ms | Confirmed VIEWER, SECURITY_ANALYST, and ADMIN permissions across settings, scans, findings, and export. |
| `Security Phase 6: SSRF Defense Guard Enforces Strict Boundary Against Internal Targets` | SSRF Defense | **PASSED** | 0.88 ms | Validated unconditional blocking of `127.0.0.1`, `localhost`, `[::1]`, `169.254.169.254`, `file://`, `gopher://`, and unapproved RFC 1918 IPs. |
| `Security H-04: CORS Origin Allowlist Validation` | CORS | **PASSED** | 0.23 ms | Validated strict origin matching; untrusted origins and spoofed subdomains are rejected. |
| `Security H-05: Server-Side Derived Audit Logging Metadata` | Audit Trail | **PASSED** | 0.22 ms | Validated that spoofed actor email/role in request body is ignored and session identity is authoritative. |
| `Security C-05: Bootstrap Endpoint Masks Secrets and Strips Password Hashes` | Information Leakage | **PASSED** | 0.16 ms | Verified password hashes and salts are stripped from user responses; integration secrets masked as `••••••••`. |

---

## 2. Node.js Security Logic & Threat Intelligence Test Suite (`securityLogic.test.ts`)

Command: `npx tsx --test src/utils/securityLogic.test.ts`  
Status: **7 / 7 PASSED (0 Failures)**

| Test Case | Focus | Result | Duration | Details |
|:---|:---|:---:|:---:|:---|
| `SSRF Guard unconditionally blocks loopback, localhost, and cloud metadata 169.254.169.254` | SSRF Guard | **PASSED** | 1.68 ms | Verified blocking of cloud metadata and loopback. |
| `SSRF Guard blocks RFC 1918 private IPs by default and allows only when lab mode + admin approval are active` | Lab Subnet Guard | **PASSED** | 0.18 ms | Enforced strict admin gate for private lab subnets. |
| `SSRF Guard blocks non-HTTP schemes like file:// and gopher://` | Protocol Schemes | **PASSED** | 0.12 ms | Verified scheme restriction to HTTP and HTTPS. |
| `LinkGuard AI detects Punycode IDN homograph and executable payload tricks` | Threat Intelligence | **PASSED** | 2.04 ms | Identified Cyrillic homograph attacks and double extensions. |
| `CVSS v3.1 calculator computes standard vectors accurately` | Vulnerability Scoring | **PASSED** | 0.54 ms | Validated standard FIRST CVSS v3.1 mathematical vectors. |
| `SPF and DMARC analyzer flags +all pass-all and p=none monitoring policies` | Email Security | **PASSED** | 0.50 ms | Detected DNS spoofing vulnerabilities. |
| `RBAC permission engine enforces ADMIN, SECURITY_ANALYST, and VIEWER boundaries` | Role Boundaries | **PASSED** | 0.22 ms | Verified role-capability mappings. |

---

## 3. Python FastAPI & Security Subsystem Test Suite (`pytest`)

Command: `& ".\backend\.venv\Scripts\python.exe" -m pytest "backend\tests"`  
Status: **29 / 29 PASSED (0 Failures)**

| Test Name | Module | Result |
|:---|:---|:---:|
| `test_ai_schema_rejects_malformed_cve_and_enforces_draft_status` | AI Copilot Security | **PASSED** |
| `test_rag_prompt_injection_xml_delimiters` | RAG Prompt Defense | **PASSED** |
| `test_argon2id_password_hash_and_verify` | Password Security | **PASSED** |
| `test_rejects_short_or_breached_passwords` | Password Policy | **PASSED** |
| `test_session_token_sha256_hashing` | Session Cryptography | **PASSED** |
| `test_1_valid_verified_target_resolves` | Target Verification | **PASSED** |
| `test_2_empty_target_rejected` | Input Validation | **PASSED** |
| `test_3_invalid_url_scheme_rejected` | SSRF Protection | **PASSED** |
| `test_4_private_ip_rejected_without_lab_approval` | Network Boundary | **PASSED** |
| `test_5_cloud_metadata_unconditionally_blocked` | Cloud Metadata Defense | **PASSED** |
| `test_6_loopback_and_localhost_unconditionally_blocked` | Loopback Defense | **PASSED** |
| `test_7_dns_rebinding_attempt_blocked` | DNS Rebinding Defense | **PASSED** |
| `test_8_redirect_to_prohibited_address_blocked` | Redirect SSRF Defense | **PASSED** |
| `test_viewer_and_analyst_rbac_matrix` | Authorization & Tenancy | **PASSED** |
| `test_tenant_isolation_columns_present_on_findings_and_rag` | Multi-Tenant Isolation | **PASSED** |
| `test_defusedxml_rejects_xxe_entity_payload` | XML/XXE Defense | **PASSED** |
| `test_valid_burp_xml_parsed_cleanly` | Scanner Parser | **PASSED** |
| `test_ssrf_blocks_loopback_and_localhost` | Core SSRF Defense | **PASSED** |
| `test_ssrf_unconditionally_blocks_cloud_metadata_in_all_modes` | Core SSRF Defense | **PASSED** |
| `test_ssrf_blocks_rfc1918_unless_lab_and_admin_approved` | Core SSRF Defense | **PASSED** |
| `test_totp_2fa_provisioning_and_replay_protection` | Multi-Factor Auth | **PASSED** |
| `test_single_use_recovery_code_hashing` | Account Recovery | **PASSED** |
| `test_control_weights_sum_to_100` | Assessment Engine | **PASSED** |
| `test_hardened_site_scores_100` | Assessment Engine | **PASSED** |
| `test_completely_insecure_site_scores_zero` | Assessment Engine | **PASSED** |
| `test_csp_upgrade_insecure_requests_alone_triggers_warning_not_pass` | Assessment Engine | **PASSED** |
| `test_hsts_inspected_on_final_https_response` | Assessment Engine | **PASSED** |
| `test_insecure_cookie_attributes_penalized` | Assessment Engine | **PASSED** |
| `test_windows_agent_hmac_signature_verification` | Windows Agent Integrity | **PASSED** |

---

## 4. Static Analysis, Typecheck & Dependency Auditing

| Check | Tool | Result | Details |
|:---|:---|:---:|:---|
| TypeScript Typecheck | `npx tsc --noEmit` | **PASSED** | 0 type errors across whole codebase. |
| Production Bundle Build | `npm run build` | **PASSED** | Client bundles compiled in 959ms without warnings. |
| Node Dependency Vulnerabilities | `npm audit` | **PASSED** | Found 0 known vulnerabilities. |
