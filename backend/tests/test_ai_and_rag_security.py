"""
Automated Pytest Suite: test_ai_and_rag_security.py, test_rbac_and_tenancy.py, test_windows_agent.py
Covers Gemini schema validation, mandatory human review gate, and prompt-injection XML wrapping.
"""
import pytest
from app.ai.gemini_client import GroundedAiAnalysisSchema, wrap_untrusted_rag_and_scanner_context


def test_ai_schema_rejects_malformed_cve_and_enforces_draft_status():
    with pytest.raises(ValueError):
        GroundedAiAnalysisSchema(
            verified_facts=["Header X-Frame-Options missing"],
            ai_risk_interpretation="Clickjacking risk",
            recommended_remediation="Add frame-ancestors 'none'",
            assumptions_and_limitations="Passive check only",
            cited_cve_ids=["CVE-FAKE-999999999"],
        )

    valid = GroundedAiAnalysisSchema(
        verified_facts=["Header X-Frame-Options missing"],
        ai_risk_interpretation="Clickjacking risk",
        recommended_remediation="Add frame-ancestors 'none'",
        assumptions_and_limitations="Passive check only",
        cited_cve_ids=["CVE-2024-12345"],
    )
    assert valid.review_status == "AI_DRAFT_PENDING_REVIEW"


def test_rag_prompt_injection_xml_delimiters():
    wrapped = wrap_untrusted_rag_and_scanner_context(
        ["OWASP CSP Guidance"], ["Server: nginx"]
    )
    assert "<untrusted_reference_context>" in wrapped
    assert "<untrusted_scanner_evidence>" in wrapped
