# MYX AI Network Trust Intelligence — Windows Quarantine & Watchdog Architecture

## 1. Principles & Safety Guarantees
1. **Scoped Adapter Isolation:** Rules are applied strictly to the target wireless interface (`InterfaceAlias="Wi-Fi"`). Wired Ethernet and VPN adapters remain untouched.
2. **Never Disable Firewall:** Windows Defender Firewall is never disabled or flushed.
3. **Unique Rule Prefix:** All rules are injected with the prefix `MYX_AI_NTI_*` and can be queried or removed cleanly.
4. **No Unrestricted DNS:** On quarantined networks, DNS is strictly constrained to explicitly pinned, trusted resolvers (`1.1.1.1`, `9.9.9.9`), eliminating rogue DNS interception and DNS tunneling.

---

## 2. Granular Network Traffic Exemptions

| Traffic Type | Destination | Direction | Action | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **Loopback** | `127.0.0.1`, `::1` | Inbound / Outbound | ALLOW | Preserves local IPC and web UI communication (ports 3000, 8000) |
| **DHCP** | `255.255.255.255`, Gateway | Outbound UDP 67/68 | ALLOW | Maintains IP lease without dropped connection |
| **Layer 2 ARP** | Native OS Stack | Both | N/A | Operates below Layer 3 IP filtering; resolves gateway |
| **Pinned DNS** | Pinned IPs (1.1.1.1, 9.9.9.9) | Outbound UDP/TCP 53 | ALLOW | Secure resolution strictly to trusted resolvers |
| **Target Wi-Fi**| Any | Outbound | BLOCK | All other traffic quarantined |

---

## 3. Multi-Tier Persistent Watchdog & Recovery
To prevent permanent isolation caused by process crashes or OS restarts:

```
[Quarantine Initiated]
        |
        +---> 1. Disk State: C:\ProgramData\MYX_AI\quarantine_state.json
        |
        +---> 2. Windows Task Scheduler: schtasks.exe (runs emergency_rollback.ps1 as SYSTEM)
        |
        +---> 3. Agent Boot Hook: Checks for expired active sessions on reboot
        |
        +---> 4. Idempotent Standalone CLI: emergency_release.bat
```

Even if the MYX AI application, Python runtime, or backend server is completely terminated, the Windows Task Scheduler independently triggers `emergency_rollback.ps1` at the designated expiry time.
