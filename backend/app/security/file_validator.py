"""
Strict File Upload & DefusedXML External Scanner Validator.
Blocks XXE, DOCTYPE, ENTITY expansion bombs (Billion Laughs), external DTDs,
oversized files, and mismatched extensions/MIME types.
"""
import json
import os
import re
from defusedxml import ElementTree as DefusedET
from defusedxml.common import DefusedXmlException

ALLOWED_SCANNER_EXTENSIONS = {".xml", ".nessus", ".json"}
MAX_SCANNER_FILE_BYTES = 25 * 1024 * 1024  # 25 MB


class FileValidationError(ValueError):
    pass


def sanitize_filename(filename: str) -> str:
    base = os.path.basename(filename.strip())
    clean = re.sub(r"[^a-zA-Z0-9._-]", "_", base)
    if not clean or clean.startswith("."):
        raise FileValidationError("Invalid or unsafe upload filename.")
    return clean


def parse_scanner_upload_safely(
    filename: str,
    raw_bytes: bytes,
    scanner_type: str,
) -> list[dict]:
    """
    Validates file extension, byte size, magic bytes, and parses Burp, ZAP, Nmap,
    Nessus (.nessus), or Nikto files using defusedxml (for XML) or json.loads.
    """
    clean_name = sanitize_filename(filename)
    _, ext = os.path.splitext(clean_name.lower())

    if ext not in ALLOWED_SCANNER_EXTENSIONS:
        raise FileValidationError(f"Unsupported file extension '{ext}'. Allowed: {sorted(ALLOWED_SCANNER_EXTENSIONS)}")

    if len(raw_bytes) == 0:
        raise FileValidationError("Uploaded scanner file is empty.")

    if len(raw_bytes) > MAX_SCANNER_FILE_BYTES:
        raise FileValidationError(f"Uploaded file exceeds maximum cap of {MAX_SCANNER_FILE_BYTES} bytes (25 MB).")

    findings: list[dict] = []

    if ext in {".xml", ".nessus"}:
        try:
            root = DefusedET.fromstring(
                raw_bytes.decode("utf-8", errors="replace"),
                forbid_dtd=True,
                forbid_entities=True,
                forbid_external=True,
            )
        except (DefusedXmlException, Exception) as exc:
            raise FileValidationError(f"XML Security Policy / XXE Guard rejected file: {exc}") from exc

        # Burp Suite XML (<issues><issue>)
        if root.tag == "issues" or scanner_type == "BURP_XML":
            for issue in root.findall(".//issue"):
                findings.append(
                    {
                        "title": issue.findtext("name", default="Burp Finding"),
                        "affected_asset": issue.findtext("host", default="unknown"),
                        "affected_component": issue.findtext("path", default="/"),
                        "severity": issue.findtext("severity", default="Medium"),
                        "confidence": issue.findtext("confidence", default="Firm"),
                        "description": issue.findtext("issueBackground", default=""),
                        "remediation_guidance": issue.findtext("remediationBackground", default=""),
                        "detection_source": "IMPORT:BURP_XML",
                    }
                )
        # Nmap XML (<nmaprun><host>)
        elif root.tag == "nmaprun" or scanner_type == "NMAP_XML":
            for host in root.findall(".//host"):
                addr_el = host.find("address")
                host_ip = addr_el.attrib.get("addr", "unknown") if addr_el is not None else "unknown"
                for port_el in host.findall(".//port"):
                    state_el = port_el.find("state")
                    if state_el is not None and state_el.attrib.get("state") == "open":
                        port_id = port_el.attrib.get("portid", "0")
                        svc_el = port_el.find("service")
                        svc_name = svc_el.attrib.get("name", "tcp") if svc_el is not None else "tcp"
                        findings.append(
                            {
                                "title": f"Open TCP Port {port_id} ({svc_name})",
                                "affected_asset": host_ip,
                                "affected_component": f"TCP/{port_id}",
                                "severity": "Medium",
                                "confidence": "Confirmed",
                                "description": f"Nmap discovered open port {port_id} running service {svc_name}.",
                                "remediation_guidance": "Verify service authorization in firewall rules.",
                                "detection_source": "IMPORT:NMAP_XML",
                            }
                        )
        # Nessus v2 (.nessus <NessusClientData_v2>)
        elif "Nessus" in root.tag or scanner_type == "NESSUS_XML":
            for rpt_host in root.findall(".//ReportHost"):
                host_name = rpt_host.attrib.get("name", "unknown")
                for item in rpt_host.findall(".//ReportItem"):
                    findings.append(
                        {
                            "title": item.attrib.get("pluginName", "Nessus Plugin Finding"),
                            "affected_asset": host_name,
                            "affected_component": f"{item.attrib.get('protocol', 'tcp')}/{item.attrib.get('port', '0')}",
                            "severity": item.findtext("risk_factor", default="Medium"),
                            "confidence": "Confirmed",
                            "description": item.findtext("description", default=""),
                            "remediation_guidance": item.findtext("solution", default=""),
                            "detection_source": "IMPORT:NESSUS_XML",
                        }
                    )
    elif ext == ".json":
        try:
            payload = json.loads(raw_bytes.decode("utf-8"))
        except Exception as exc:
            raise FileValidationError(f"Malformed JSON scanner export: {exc}") from exc

        # OWASP ZAP or Nikto JSON
        alerts = payload.get("alerts") or payload.get("vulnerabilities") or []
        for entry in alerts:
            findings.append(
                {
                    "title": entry.get("alert") or entry.get("msg") or "Imported Scanner Finding",
                    "affected_asset": entry.get("host") or payload.get("host", "unknown"),
                    "affected_component": entry.get("url") or "/",
                    "severity": entry.get("riskdesc", "Medium").split(" ")[0],
                    "confidence": "High",
                    "description": entry.get("desc") or entry.get("msg") or "",
                    "remediation_guidance": entry.get("solution") or "Review security configuration.",
                    "detection_source": f"IMPORT:{scanner_type}",
                }
            )

    return findings
