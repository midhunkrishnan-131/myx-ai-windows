# MYX AI Network Trust Intelligence — Deterministic Risk Engine Specification

## 1. Mathematical Scoring & Confidence Formulation

### Risk Score Formula
$$\text{RiskScore} = \min\left(100, \sum_{i=1}^{n} \text{Penalty}(R_i)\right)$$

### Confidence Rating Formula
$$\text{Confidence} = \max\left(10, \min\left(100, 100 - \sum \text{MissingTelemetryPenalties}\right)\right)$$

- Missing Gateway MAC: $-25\%$
- Missing DNS Servers: $-20\%$
- Hidden / Unresolved SSID: $-30\%$

---

## 2. Rule Catalog

| Rule ID | Name | Penalty | Severity | Trigger Criteria |
| :--- | :--- | :---: | :---: | :--- |
| **`NTI-R01`** | Cleartext Open Wireless Network | $+40$ | High | Auth is Open or Cipher is None |
| **`NTI-R02`** | Deprecated Cipher Suite (WEP/TKIP) | $+50$ | High | Cipher negotiates WEP or TKIP |
| **`NTI-R03`** | Active Cryptographic Downgrade | $+65$ | Critical | Baseline was WPA3/Enterprise, observed is WPA2/Open |
| **`NTI-R04`** | Gateway MAC Drift / ARP Spoofing | $+45$ | High | Gateway MAC differs from baseline on same SSID |
| **`NTI-R05`** | Rogue DNS Server Injected | $+35$ | Moderate | DNS resolvers differ from baseline |
| **`NTI-R06`** | Evil-Twin SSID Impersonation | $+70$ | Critical | SSID match + OUI discrepancy + crypto diff |
| **`NTI-R07`** | Captive Portal Interception | $+30$ | Moderate | HTTP probe 302 redirect on production network |
| **`NTI-R08`** | Unapproved Unknown Network | $+25$ | Moderate | No baseline profile exists for this SSID |
| **`NTI-R09`** | Unrecognized Access Point BSSID | $+15$ | Low | New BSSID without matching OUI |
| **`NTI-R10`** | Incomplete Telemetry / Adapter Blinded | $+15$ | Low | Missing critical parameters; uncertainty penalty |

---

## 3. Severity Tiers & Balanced Protection Mode Responses

| Score Range | Severity Tier | Balanced Protection Mode Action |
| :---: | :---: | :--- |
| **0–24** | **LOW** | Continue passive background monitoring. |
| **25–49** | **MODERATE** | Anomaly detected. Notify user and recommend verification. |
| **50–74** | **HIGH** | High-confidence threat. Apply policy-approved selective traffic restriction. |
| **75–100** | **CRITICAL** | Severe wireless threat. Apply scoped Windows Firewall quarantine. |
