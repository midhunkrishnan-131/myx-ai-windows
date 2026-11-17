"""
SQLAlchemy 2.0 Normalized Database Schema (31 Tables) for MYX AI (Windows Edition).
Supports PostgreSQL 15+ (Neon, Supabase, Local) + pgvector with SQLite test fallback.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())



class Base(DeclarativeBase):
    pass


# 1. users
class User(Base):
    __tablename__ = "users"
    id = Column(String(36), primary_key=True, default=new_uuid)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(512), nullable=False)
    full_name = Column(String(255), nullable=False)
    job_title = Column(String(255), default="Security Analyst")
    is_active = Column(Boolean, default=True, nullable=False)
    is_email_verified = Column(Boolean, default=False, nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# 2. organizations
class Organization(Base):
    __tablename__ = "organizations"
    id = Column(String(36), primary_key=True, default=new_uuid)
    name = Column(String(255), nullable=False)
    slug = Column(String(128), unique=True, index=True, nullable=False)
    lab_targets_allowed = Column(Boolean, default=False, nullable=False)
    default_scan_rate_limit = Column(Integer, default=30, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# 3. roles
class Role(Base):
    __tablename__ = "roles"
    id = Column(String(36), primary_key=True, default=new_uuid)
    name = Column(String(64), unique=True, nullable=False)  # ADMIN, SECURITY_ANALYST, VIEWER
    description = Column(String(512), nullable=False)
    is_system_role = Column(Boolean, default=True, nullable=False)


# 4. permissions
class Permission(Base):
    __tablename__ = "permissions"
    id = Column(String(36), primary_key=True, default=new_uuid)
    code = Column(String(128), unique=True, nullable=False)
    description = Column(String(512), nullable=False)


# 5. role_permissions
class RolePermission(Base):
    __tablename__ = "role_permissions"
    id = Column(String(36), primary_key=True, default=new_uuid)
    role_id = Column(String(36), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    permission_id = Column(String(36), ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False)


# 6. organization_memberships
class OrganizationMembership(Base):
    __tablename__ = "organization_memberships"
    __table_args__ = (UniqueConstraint("organization_id", "user_id", name="uq_org_user"),)
    id = Column(String(36), primary_key=True, default=new_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role_id = Column(String(36), ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False)
    is_primary = Column(Boolean, default=True, nullable=False)
    joined_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 7. user_sessions
class UserSession(Base):
    __tablename__ = "user_sessions"
    id = Column(String(36), primary_key=True, default=new_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    session_token_hash = Column(String(128), unique=True, index=True, nullable=False)
    csrf_token_hash = Column(String(128), nullable=False)
    ip_address = Column(String(64), nullable=False)
    user_agent = Column(String(512), nullable=False)
    is_2fa_verified = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_active_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 8. email_verification_tokens
class EmailVerificationToken(Base):
    __tablename__ = "email_verification_tokens"
    id = Column(String(36), primary_key=True, default=new_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(128), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 9. password_reset_tokens
class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id = Column(String(36), primary_key=True, default=new_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(128), unique=True, index=True, nullable=False)
    requested_ip = Column(String(64), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 10. totp_settings
class TotpSetting(Base):
    __tablename__ = "totp_settings"
    id = Column(String(36), primary_key=True, default=new_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    encrypted_secret = Column(Text, nullable=False)
    is_enabled = Column(Boolean, default=False, nullable=False)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    last_verified_timestep = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# 11. totp_recovery_codes
class TotpRecoveryCode(Base):
    __tablename__ = "totp_recovery_codes"
    id = Column(String(36), primary_key=True, default=new_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    code_hash = Column(String(256), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 12. authorized_targets
class AuthorizedTarget(Base):
    __tablename__ = "authorized_targets"
    id = Column(String(36), primary_key=True, default=new_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    target_type = Column(String(32), nullable=False)  # DOMAIN, URL, IPV4, CIDR, WINDOWS_HOST
    target_value = Column(String(512), nullable=False)
    display_name = Column(String(255), nullable=False)
    environment = Column(String(32), default="PRODUCTION", nullable=False)
    verification_status = Column(String(32), default="PENDING", nullable=False)
    verification_method = Column(String(32), nullable=False)
    verification_token = Column(String(255), nullable=False)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 13. authorization_records
class AuthorizationRecord(Base):
    __tablename__ = "authorization_records"
    id = Column(String(36), primary_key=True, default=new_uuid)
    target_id = Column(String(36), ForeignKey("authorized_targets.id", ondelete="CASCADE"), nullable=False)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    attested_by_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    authorization_type = Column(String(64), nullable=False)
    scope_notes = Column(Text, nullable=True)
    attested_ip = Column(String(64), nullable=False)
    user_agent = Column(String(512), nullable=False)
    valid_from = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    valid_until = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 14. assessments
class Assessment(Base):
    __tablename__ = "assessments"
    id = Column(String(36), primary_key=True, default=new_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    target_id = Column(String(36), ForeignKey("authorized_targets.id", ondelete="SET NULL"), nullable=True)
    module_type = Column(String(32), nullable=False)  # WEBSITE, NETWORK, WIFI, WINDOWS, LINKGUARD, SSL_TLS, DNS
    status = Column(String(32), default="QUEUED", nullable=False)
    initiated_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    profile_name = Column(String(128), nullable=False)
    summary_json = Column(JSON, default=dict)
    risk_score = Column(Float, default=0.0)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 15. assessment_tasks
class AssessmentTask(Base):
    __tablename__ = "assessment_tasks"
    id = Column(String(36), primary_key=True, default=new_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    task_name = Column(String(128), nullable=False)
    status = Column(String(32), default="RUNNING", nullable=False)
    progress_percent = Column(Integer, default=0, nullable=False)
    started_at = Column(DateTime(timezone=True), default=utcnow)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    diagnostics_json = Column(JSON, default=dict)


# 16. assessment_results
class AssessmentResult(Base):
    __tablename__ = "assessment_results"
    id = Column(String(36), primary_key=True, default=new_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), index=True, nullable=False)
    check_code = Column(String(64), nullable=False)
    check_title = Column(String(255), nullable=False)
    category = Column(String(128), nullable=False)
    status = Column(String(32), nullable=False)  # PASS, WARNING, FAIL, INFO, UNSUPPORTED, REQUIRES_ELEVATION
    severity = Column(String(32), nullable=False)
    confidence = Column(String(32), nullable=False)
    raw_evidence_json = Column(JSON, default=dict)
    remediation_text = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 17. findings
class Finding(Base):
    __tablename__ = "findings"
    id = Column(String(36), primary_key=True, default=new_uuid)
    finding_code = Column(String(64), index=True, nullable=False)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="SET NULL"), nullable=True)
    target_id = Column(String(36), ForeignKey("authorized_targets.id", ondelete="SET NULL"), nullable=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=False)
    affected_asset = Column(String(512), nullable=False)
    affected_component = Column(String(512), nullable=True)
    severity = Column(String(32), nullable=False)
    confidence = Column(String(32), nullable=False)
    status = Column(String(32), default="Open", nullable=False)
    cvss_version = Column(String(16), default="3.1")
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(128), nullable=True)
    cve_ids_json = Column(JSON, default=list)
    cwe_id = Column(String(128), nullable=True)
    owasp_category = Column(String(128), nullable=True)
    detection_source = Column(String(128), nullable=False)
    remediation_guidance = Column(Text, nullable=False)
    assigned_analyst_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    first_detected_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# 18. finding_evidence
class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    id = Column(String(36), primary_key=True, default=new_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=False)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    evidence_type = Column(String(64), nullable=False)
    title = Column(String(255), nullable=False)
    content_text = Column(Text, nullable=True)
    file_storage_path = Column(String(512), nullable=True)
    mime_type = Column(String(128), nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    sha256_hash = Column(String(64), nullable=False)
    uploaded_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 19. finding_comments
class FindingComment(Base):
    __tablename__ = "finding_comments"
    id = Column(String(36), primary_key=True, default=new_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=False)
    author_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    comment_body = Column(Text, nullable=False)
    is_retest_note = Column(Boolean, default=False, nullable=False)
    retest_outcome = Column(String(32), nullable=True)  # PASSED, FAILED, PARTIAL
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# 20. reports
class Report(Base):
    __tablename__ = "reports"
    id = Column(String(36), primary_key=True, default=new_uuid)
    report_code = Column(String(64), unique=True, index=True, nullable=False)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    title = Column(String(512), nullable=False)
    project_name = Column(String(255), nullable=False)
    scope_summary = Column(Text, nullable=False)
    assessment_date_start = Column(DateTime(timezone=True), nullable=True)
    assessment_date_end = Column(DateTime(timezone=True), nullable=True)
    executive_summary = Column(Text, nullable=True)
    technical_summary = Column(Text, nullable=True)
    methodology_notes = Column(Text, nullable=True)
    status = Column(String(32), default="DRAFT", nullable=False)  # DRAFT, IN_REVIEW, APPROVED, ARCHIVED
    current_version_number = Column(String(32), default="v1.0", nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    assigned_reviewer_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# 21. report_versions
class ReportVersion(Base):
    __tablename__ = "report_versions"
    id = Column(String(36), primary_key=True, default=new_uuid)
    report_id = Column(String(36), ForeignKey("reports.id", ondelete="CASCADE"), index=True, nullable=False)
    version_number = Column(String(32), nullable=False)
    snapshot_json = Column(JSON, default=dict, nullable=False)
    change_summary = Column(String(512), nullable=False)
    is_ai_generated_draft = Column(Boolean, default=True, nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 22. external_imports
class ExternalImport(Base):
    __tablename__ = "external_imports"
    id = Column(String(36), primary_key=True, default=new_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    uploaded_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    scanner_type = Column(String(32), nullable=False)  # BURP_XML, ZAP_JSON, ZAP_XML, NMAP_XML, NESSUS_XML, NIKTO
    original_filename = Column(String(255), nullable=False)
    stored_file_path = Column(String(512), nullable=False)
    file_sha256 = Column(String(64), nullable=False)
    file_size_bytes = Column(Integer, nullable=False)
    parse_status = Column(String(32), default="PENDING", nullable=False)
    findings_imported_count = Column(Integer, default=0, nullable=False)
    error_details = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 23. integrations
class Integration(Base):
    __tablename__ = "integrations"
    id = Column(String(36), primary_key=True, default=new_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    provider = Column(String(64), nullable=False)
    status = Column(String(32), default="DISCONNECTED", nullable=False)
    encrypted_credentials_json = Column(Text, nullable=True)
    config_metadata_json = Column(JSON, default=dict)
    last_tested_at = Column(DateTime(timezone=True), nullable=True)
    last_error_message = Column(Text, nullable=True)
    updated_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# 24. windows_agents
class WindowsAgent(Base):
    __tablename__ = "windows_agents"
    id = Column(String(36), primary_key=True, default=new_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    hostname = Column(String(255), nullable=False)
    display_name = Column(String(255), nullable=False)
    os_edition = Column(String(128), nullable=False)
    os_version = Column(String(64), nullable=False)
    os_build = Column(String(64), nullable=False)
    agent_version = Column(String(32), nullable=False)
    privilege_level = Column(String(32), default="STANDARD_USER", nullable=False)
    status = Column(String(32), default="ACTIVE", nullable=False)
    auth_token_hash = Column(String(128), unique=True, index=True, nullable=False)
    hmac_secret_encrypted = Column(Text, nullable=False)
    last_heartbeat_at = Column(DateTime(timezone=True), nullable=True)
    last_ip_address = Column(String(64), nullable=True)
    enrolled_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    revoked_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 25. agent_enrollment_records
class AgentEnrollmentRecord(Base):
    __tablename__ = "agent_enrollment_records"
    id = Column(String(36), primary_key=True, default=new_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    enrollment_token_hash = Column(String(128), unique=True, index=True, nullable=False)
    intended_hostname = Column(String(255), nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    claimed_by_agent_id = Column(String(36), ForeignKey("windows_agents.id", ondelete="SET NULL"), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    claimed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 26. agent_activity_logs
class AgentActivityLog(Base):
    __tablename__ = "agent_activity_logs"
    id = Column(String(36), primary_key=True, default=new_uuid)
    agent_id = Column(String(36), ForeignKey("windows_agents.id", ondelete="CASCADE"), index=True, nullable=False)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    event_type = Column(String(64), nullable=False)
    details_json = Column(JSON, default=dict)
    ip_address = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 27. notifications
class Notification(Base):
    __tablename__ = "notifications"
    id = Column(String(36), primary_key=True, default=new_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    severity = Column(String(32), default="INFO", nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    link_path = Column(String(255), nullable=True)
    is_read = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 28. audit_logs (Immutable append-only security audit trail)
class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String(36), primary_key=True, default=new_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="SET NULL"), index=True, nullable=True)
    actor_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    actor_role = Column(String(64), nullable=True)
    event_category = Column(String(64), nullable=False)
    action = Column(String(128), nullable=False)
    resource_type = Column(String(64), nullable=False)
    resource_id = Column(String(128), nullable=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(512), nullable=True)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 29. ai_conversations
class AiConversation(Base):
    __tablename__ = "ai_conversations"
    id = Column(String(36), primary_key=True, default=new_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(255), nullable=False)
    attached_finding_ids_json = Column(JSON, default=list)
    attached_assessment_ids_json = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# 30. ai_messages & ai_usage_logs
class AiMessage(Base):
    __tablename__ = "ai_messages"
    id = Column(String(36), primary_key=True, default=new_uuid)
    conversation_id = Column(String(36), ForeignKey("ai_conversations.id", ondelete="CASCADE"), index=True, nullable=False)
    role = Column(String(32), nullable=False)  # user, assistant, system
    content = Column(Text, nullable=False)
    structured_response_json = Column(JSON, nullable=True)
    citations_json = Column(JSON, default=list)
    model_used = Column(String(128), nullable=False)
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    latency_ms = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 31. rag_documents & rag_document_chunks
class RagDocument(Base):
    __tablename__ = "rag_documents"
    id = Column(String(36), primary_key=True, default=new_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=True)
    title = Column(String(255), nullable=False)
    source_type = Column(String(64), nullable=False)
    source_reference = Column(String(255), nullable=False)
    is_global_reference = Column(Boolean, default=False, nullable=False)
    chunk_count = Column(Integer, default=0, nullable=False)
    uploaded_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class RagDocumentChunk(Base):
    __tablename__ = "rag_document_chunks"
    id = Column(String(36), primary_key=True, default=new_uuid)
    document_id = Column(String(36), ForeignKey("rag_documents.id", ondelete="CASCADE"), index=True, nullable=False)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=True)
    chunk_index = Column(Integer, nullable=False)
    section_heading = Column(String(255), nullable=True)
    content_text = Column(Text, nullable=False)
    token_count = Column(Integer, default=0)
    embedding_json = Column(JSON, nullable=True)  # Mapped to Vector(768) on PostgreSQL pgvector
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 32. network_profiles (Personal & Organization Trusted Baselines)
class NetworkProfile(Base):
    __tablename__ = "network_profiles"
    id = Column(String(36), primary_key=True, default=new_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    ssid = Column(String(128), nullable=False, index=True)
    profile_type = Column(String(32), default="PERSONAL", nullable=False)  # PERSONAL or ORGANIZATION
    status = Column(String(32), default="PENDING_REVIEW", nullable=False)  # APPROVED, PENDING_REVIEW, REJECTED
    baseline_fingerprint = Column(String(128), nullable=False)
    baseline_bssids = Column(JSON, default=list)
    baseline_auth = Column(String(64), nullable=False)
    baseline_cipher = Column(String(64), nullable=False)
    baseline_gateway_ip = Column(String(64), nullable=True)
    baseline_gateway_mac = Column(String(64), nullable=True)
    baseline_dns = Column(JSON, default=list)
    approved_by = Column(String(255), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# 33. network_observations (Live & Historical WLAN Observations)
class NetworkObservation(Base):
    __tablename__ = "network_observations"
    id = Column(String(36), primary_key=True, default=new_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True)
    host_id = Column(String(128), nullable=False, index=True)
    ssid = Column(String(128), nullable=False)
    bssid = Column(String(64), nullable=False)
    visible_bssids = Column(JSON, default=list)
    auth_type = Column(String(64), nullable=False)
    cipher = Column(String(64), nullable=False)
    signal_quality = Column(Integer, default=0)
    channel = Column(Integer, nullable=True)
    band = Column(String(16), nullable=True)
    gateway_ip = Column(String(64), nullable=True)
    gateway_mac = Column(String(64), nullable=True)
    dns_servers = Column(JSON, default=list)
    dhcp_server = Column(String(64), nullable=True)
    ip_address = Column(String(64), nullable=True)
    captive_portal_detected = Column(Boolean, default=False)
    captive_portal_url = Column(String(512), nullable=True)
    observation_metadata = Column(JSON, default=dict)
    observed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 34. network_risk_assessments (Deterministic Rule Evaluations & Confidence)
class NetworkRiskAssessment(Base):
    __tablename__ = "network_risk_assessments"
    id = Column(String(36), primary_key=True, default=new_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=True)
    observation_id = Column(String(36), nullable=True)
    profile_id = Column(String(36), ForeignKey("network_profiles.id", ondelete="SET NULL"), nullable=True)
    risk_score = Column(Integer, nullable=False)  # 0 to 100
    severity = Column(String(32), nullable=False)  # LOW, MODERATE, HIGH, CRITICAL
    confidence = Column(Integer, nullable=False)  # 0 to 100
    detected_signals = Column(JSON, default=list)
    field_diffs = Column(JSON, default=list)
    evidence = Column(JSON, default=dict)
    explanation = Column(Text, nullable=False)
    recommended_action = Column(Text, nullable=False)
    policy_applied = Column(String(128), default="Balanced Protection Mode")
    assessed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 35. network_quarantine_sessions (Scoped Windows Firewall Containment & Watchdog State)
class NetworkQuarantineSession(Base):
    __tablename__ = "network_quarantine_sessions"
    id = Column(String(36), primary_key=True, default=new_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    host_id = Column(String(128), nullable=False)
    target_interface = Column(String(128), default="Wi-Fi")
    isolation_level = Column(String(64), default="BALANCED_QUARANTINE")  # BALANCED_QUARANTINE, RESTRICTED_INTERNET, FULL_ISOLATION
    applied_rules = Column(JSON, default=list)
    trigger_reason = Column(Text, nullable=False)
    risk_score = Column(Integer, nullable=False)
    timeout_seconds = Column(Integer, default=900)  # 15 min failsafe default
    expires_at = Column(DateTime(timezone=True), nullable=False)
    status = Column(String(32), default="ACTIVE")  # ACTIVE, ROLLED_BACK, EMERGENCY_RELEASED, EXPIRED
    released_by = Column(String(255), nullable=True)
    released_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# 36. network_protection_policies (Configurable Thresholds & Pinned DNS Allowlist)
class NetworkProtectionPolicy(Base):
    __tablename__ = "network_protection_policies"
    id = Column(String(36), primary_key=True, default=new_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=True)
    policy_name = Column(String(128), nullable=False)
    mode = Column(String(32), default="BALANCED")  # BALANCED, STRICT, AUDIT_ONLY
    low_threshold = Column(Integer, default=0)
    moderate_threshold = Column(Integer, default=25)
    high_threshold = Column(Integer, default=50)
    critical_threshold = Column(Integer, default=75)
    allowed_gateways = Column(JSON, default=list)
    allowed_dns = Column(JSON, default=list)
    auto_quarantine_enabled = Column(Boolean, default=True)
    watchdog_timeout_sec = Column(Integer, default=900)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

