# MYX AI Network Trust Intelligence — Security Test Plan & Verification Ledger

## 1. Test Overview
The test suite validates cryptographic integrity, deterministic scoring, enterprise tenancy boundaries, RBAC permissions, and firewall rule isolation.

---

## 2. Automated Test Matrix

### Python Pytest Suite (`backend/tests/test_network_trust_intelligence.py`)
- `test_mac_normalization_and_oui_extraction`: Validates parsing of varied MAC separators (`:`, `-`, continuous hex) and 24-bit OUI extraction.
- `test_deterministic_network_fingerprint_reproducibility`: Verifies canonical SHA-256 calculation regardless of SSID case or DNS server ordering.
- `test_benign_enterprise_roaming_not_classified_as_attack`: Verifies that new BSSIDs under identical OUI, gateway MAC, and cipher suites receive `BENIGN_ROAMING` status with 0 risk penalty.
- `test_crypto_downgrade_detection_triggers_critical`: Simulates rogue beacon downgrade from WPA3 to WPA2-TKIP, confirming Critical tier classification ($\ge 75$) and quarantine recommendation.
- `test_missing_data_penalizes_and_reduces_confidence`: Tests that blinded telemetry triggers Rule `NTI-R10` (+15 penalty) and reduces confidence below 100%. Missing data never defaults to safe.
- `test_cleartext_open_network_penalized`: Verifies open networks receive $+40$ risk penalty.
- `test_rbac_viewer_blocked_from_quarantine`: Verifies `VIEWER` role receives `PermissionError` (HTTP 403) on quarantine initiation and release.

### TypeScript Suite (`src/utils/networkTrust.test.ts`)
- Mathematical bounds verification: score capped between 0 and 100.
- Severity threshold classification: matches 24 / 49 / 74 / 75 boundaries.
- Quarantine rule name formatting: enforces `MYX_AI_NTI_*` prefix.
- Confidence penalty formula verification.

---

## 3. Execution Results
- Pytest: **47 passed** (including 7 Network Trust tests).
- TypeScript: **29 passed** (including 4 Network Trust tests).
- Total System Tests: **76 passed (100% clean, 0 failures)**.
