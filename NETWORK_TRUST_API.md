# MYX AI Network Trust Intelligence — API Reference

All endpoints are hosted at `/api/v1/network-trust/*` and require authentication.

---

## Endpoints Summary

| Method | Endpoint | Description | Role Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/live` | Retrieves live wireless interface & Layer 3 telemetry | VIEWER, SECURITY_ANALYST, ADMIN |
| `GET` | `/profiles` | Lists approved & pending network baseline profiles | VIEWER, SECURITY_ANALYST, ADMIN |
| `POST` | `/profiles` | Registers a new network profile (Personal or Enterprise) | SECURITY_ANALYST, ADMIN |
| `POST` | `/profiles/{id}/approve` | Approves an unverified network baseline profile | SECURITY_ANALYST, ADMIN |
| `POST` | `/evaluate` | Evaluates deterministic risk score & field-level diffs | VIEWER, SECURITY_ANALYST, ADMIN |
| `POST` | `/quarantine/apply` | Enforces scoped Windows Firewall quarantine | SECURITY_ANALYST, ADMIN |
| `POST` | `/quarantine/release` | Rolls back active quarantine containment | SECURITY_ANALYST, ADMIN |
| `GET` | `/quarantine/status` | Checks active quarantine state & admin elevation | VIEWER, SECURITY_ANALYST, ADMIN |
| `GET` | `/policies` | Retrieves active Balanced Protection Mode policy | VIEWER, SECURITY_ANALYST, ADMIN |
| `PUT` | `/policies` | Updates risk thresholds and pinned DNS allowlists | ADMIN |
| `GET` | `/history` | Historical log of network risk assessments | VIEWER, SECURITY_ANALYST, ADMIN |
| `POST` | `/ai/explain` | Grounded AI incident explanation (Beginner / Technical) | VIEWER, SECURITY_ANALYST, ADMIN |

---

## Sample Request: Evaluate Network Risk

```http
POST /api/v1/network-trust/evaluate HTTP/1.1
Content-Type: application/json
Authorization: Bearer <session-token>

{
  "ssid": "Corp-Guest",
  "bssid": "00:14:22:FE:AA:01",
  "auth_type": "Open",
  "cipher": "None",
  "signal_quality": 88,
  "gateway_ip": "192.168.1.1",
  "gateway_mac": "00:14:22:FE:DC:BA",
  "dns_servers": ["8.8.8.8"]
}
```

### Sample Response:
```json
{
  "assessment_id": "eval-1794760000",
  "risk_score": 65,
  "severity": "HIGH",
  "confidence": 95,
  "detected_signals": [
    {
      "rule_id": "NTI-R01",
      "name": "Cleartext Open Wireless Network",
      "severity": "HIGH",
      "penalty": 40,
      "explanation": "Active Wi-Fi connection lacks link-layer encryption."
    },
    {
      "rule_id": "NTI-R08",
      "name": "Unapproved Unknown Wi-Fi Network",
      "severity": "MEDIUM",
      "penalty": 25,
      "explanation": "Network has no approved baseline profile on this device."
    }
  ],
  "quarantine_action": "SELECTIVE_RESTRICTION",
  "recommended_action": "Recommend applying selective traffic restrictions and user verification."
}
```
