# MYX AI Network Trust Intelligence — Architecture Specification

**Brand:** MYX AI by Midhun Krishnan ("Discover. Detect. Defend.")  
**System Edition:** Microsoft Windows Edition (Windows 10 20H2+ & Windows 11 21H2–24H2+)  
**Status:** Production Standard v2.0  

---

## 1. Executive Overview
**MYX AI Network Trust Intelligence (NTI)** protects personal Windows endpoints and enterprise managed workstations against unauthorized wireless network exposure, Evil-Twin access point impersonation, rogue DHCP/DNS redirection, and malicious protocol downgrades.

Operating under **Balanced Protection Mode**, the system continuously monitors the host's wireless environment, computes deterministic fingerprints, compares observations against personal and enterprise baselines, evaluates an explainable 0–100 risk score, and coordinates scoped Windows Defender Firewall quarantine containment without disrupting core OS services or management communication.

---

## 2. Architectural Blueprint

```
+-------------------------------------------------------------------------+
|                       MYX AI React Web Platform                         |
|  - Live Monitor    - Profiles Ledger   - Risk Engine    - Quarantine    |
+------------------------------------+------------------------------------+
                                     | REST / CSRF / Session Auth
                                     v
+------------------------------------+------------------------------------+
|                      server.ts (Express Gateway)                        |
|  - Port 3000       - RBAC Guard        - Reverse Proxy  - Local Fallback|
+------------------------------------+------------------------------------+
                                     | Proxy to /api/v1/network-trust/*
                                     v
+------------------------------------+------------------------------------+
|                     FastAPI Analytical Backend                          |
|  - Port 8000       - SQLAlchemy Models - Fingerprinting - Risk Engine   |
+------------------------------------+------------------------------------+
                                     | Dispatches Signed Directives
                                     v
+------------------------------------+------------------------------------+
|             Authenticated Windows Agent (ELEVATED_ADMIN)                |
|  - WlanAPI / netsh - Iphlpapi / ARP    - Task Scheduler - State File    |
+------------------------------------+------------------------------------+
                                     | Scoped NetFirewallRule (MYX_AI_NTI_*)
                                     v
+-------------------------------------------------------------------------+
|                      Windows Defender Firewall                          |
|  [Allowed: Loopback (127.0.0.1), DHCP (67/68), Pinned DNS (1.1.1.1)]   |
|  [Blocked: All other outbound Layer 3/4 traffic on target Wi-Fi adapter]|
+-------------------------------------------------------------------------+
```

---

## 3. Core Subsystems

### 3.1 Network Data Collector
- Collects live wireless beacon parameters: SSID, BSSID, Signal quality, Auth algorithm, and Cipher suite.
- Gathers Layer 3 properties: Default gateway IP, Gateway MAC via ARP cache, DHCP server, and active DNS resolvers.
- Detects Windows 11 (24H2) Location Permission boundaries and handles missing fields without guessing.

### 3.2 Network Fingerprint & Field Diff Engine
- Computes SHA-256 baseline signatures.
- Performs field-level delta analysis across 8 structural properties.
- Distinguishes **Benign Enterprise Roaming** from attack anomalies when an authorized multi-AP environment shares identical OUI, gateway MAC, and encryption profiles.

### 3.3 Deterministic Rule-Based Risk Engine
- 10 authoritative rules (`NTI-R01` through `NTI-R10`).
- Mathematically bounded score (0–100) and separate confidence rating (0–100).
- Strict separation: AI Copilot provides natural language explanation; AI never alters authoritative scores.

### 3.4 Scoped Windows Firewall Quarantine Controller
- Manages rules prefixed with `MYX_AI_NTI_*` scoped to the wireless interface alias.
- Multi-tier persistent watchdog: Task Scheduler (`schtasks.exe`), disk state (`quarantine_state.json`), and agent startup hooks ensure recovery survives reboots and crashes.
- Granular exemptions: Loopback, DHCP lease renewal, and pinned trusted DNS.
