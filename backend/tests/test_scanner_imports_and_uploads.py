"""
Automated Pytest Suite: test_scanner_imports_and_uploads.py
Covers Burp/Nmap/Nessus XML parsing and rejection of XXE / DOCTYPE / ENTITY payloads via defusedxml.
"""
import pytest
from app.security.file_validator import FileValidationError, parse_scanner_upload_safely


def test_defusedxml_rejects_xxe_entity_payload():
    malicious_xxe = b"""<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [ <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <issues><issue><name>&xxe;</name></issue></issues>
    """
    with pytest.raises(FileValidationError):
        parse_scanner_upload_safely("evil_burp.xml", malicious_xxe, "BURP_XML")


def test_valid_burp_xml_parsed_cleanly():
    clean_burp = b"""<?xml version="1.0" encoding="UTF-8"?>
    <issues>
      <issue>
        <name>Strict-Transport-Security Header Missing</name>
        <host>https://portal.myx-defense-demo.org</host>
        <path>/</path>
        <severity>Medium</severity>
        <confidence>Certain</confidence>
      </issue>
    </issues>
    """
    findings = parse_scanner_upload_safely("clean_burp.xml", clean_burp, "BURP_XML")
    assert len(findings) == 1
    assert findings[0]["detection_source"] == "IMPORT:BURP_XML"
