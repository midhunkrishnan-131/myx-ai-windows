# MYX AI Network Trust Intelligence — Network Fingerprinting Specification

## 1. Overview
A network fingerprint in MYX AI represents the verifiable identity of an 802.11 wireless network coupled with its Layer 3 IP configuration. Rather than relying on an opaque hash alone, MYX AI records both a deterministic canonical signature and structured field-level baselines.

---

## 2. Canonical Signature Formula
To support multi-AP roaming across enterprise campuses without invalidating the baseline identity, the primary signature omits individual AP BSSIDs and hashes invariant structural properties:

$$\text{Signature} = \text{SHA256}\left(\text{SSID} \parallel \text{AUTH} \parallel \text{CIPHER} \parallel \text{GW\_MAC} \parallel \text{SORTED\_DNS}\right)$$

---

## 3. Field-Level Attributes

| Attribute | Normalization | Description |
| :--- | :--- | :--- |
| **`ssid`** | Stripped, Lowercase | Case-insensitive network name |
| **`auth_type`** | Uppercase String | `WPA3-SAE`, `WPA3-ENTERPRISE`, `WPA2-PERSONAL`, `OPEN` |
| **`cipher`** | Uppercase String | `CCMP`, `GCMP-256`, `TKIP`, `NONE` |
| **`gateway_mac`** | Colon-separated uppercase | Standard 48-bit ARP hardware address |
| **`gateway_ip`** | IPv4 / IPv6 notation | Default router address |
| **`dns_servers`** | Alphabetically sorted list | Resolver IP addresses assigned via DHCP or static config |
| **`baseline_bssids`**| Array of normalized MACs | Known access points broadcasting this network |

---

## 4. Benign Enterprise Roaming vs. Evil-Twin Detection
1. **Benign Roaming:**
   - Condition: Observed BSSID is not in `baseline_bssids`, BUT the BSSID's Organizationally Unique Identifier (OUI) matches the baseline vendor, the gateway MAC is identical, and encryption parameters match.
   - Verdict: `BENIGN_ROAMING` (0 penalty, Informational log).
2. **Evil-Twin Impersonation:**
   - Condition: Observed SSID matches a trusted profile, but the authentication is downgraded (e.g., WPA3 to WPA2-Personal/Open) or the gateway MAC differs.
   - Verdict: `CRITICAL_ANOMALY` (+65 to +70 penalty, Critical risk).
