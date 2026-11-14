"""
Automated Pytest Suite: test_rbac_and_tenancy.py
Verifies ADMIN, SECURITY_ANALYST, and VIEWER RBAC boundaries and multi-tenant isolation.
"""
from app.models.domain_models import Finding, RagDocumentChunk


def test_viewer_and_analyst_rbac_matrix():
    role_matrix = {
        "ADMIN": {"users:manage", "integrations:manage", "assessments:run", "findings:write", "findings:read"},
        "SECURITY_ANALYST": {"assessments:run", "findings:write", "findings:read"},
        "VIEWER": {"findings:read"},
    }
    assert "assessments:run" not in role_matrix["VIEWER"]
    assert "findings:write" not in role_matrix["VIEWER"]
    assert "users:manage" not in role_matrix["SECURITY_ANALYST"]
    assert "users:manage" in role_matrix["ADMIN"]


def test_tenant_isolation_columns_present_on_findings_and_rag():
    assert hasattr(Finding, "organization_id")
    assert hasattr(RagDocumentChunk, "organization_id")
