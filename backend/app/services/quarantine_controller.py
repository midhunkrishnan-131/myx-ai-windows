"""
MYX AI Network Trust Intelligence — Backend Quarantine Controller Service.
Brand: MYX AI by Midhun Krishnan ("Discover. Detect. Defend.")

Manages NetworkQuarantineSession lifecycle, RBAC enforcement, and dispatches
authoritative commands to the local or remote Windows Agent.
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session

from app.models.domain_models import NetworkQuarantineSession, AuditLog

# Import local Windows agent quarantine manager if available
try:
    from windows_agent.quarantine_manager import (
        apply_scoped_firewall_quarantine,
        rollback_firewall_quarantine,
        read_quarantine_state,
        is_elevated_admin,
    )
except ImportError:
    # Fallback mock for non-Windows test environments
    def apply_scoped_firewall_quarantine(*args, **kwargs):
        return {"status": "MOCK_ACTIVE", "rules_applied": ["MYX_AI_NTI_MOCK_RULE"]}
    def rollback_firewall_quarantine():
        return {"status": "MOCK_ROLLED_BACK", "rules_removed": 1}
    def read_quarantine_state():
        return None
    def is_elevated_admin():
        return True


def initiate_network_quarantine(
    db: Session,
    host_id: str,
    reason: str,
    risk_score: int,
    user_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    user_role: str = "ADMIN",
    target_interface: str = "Wi-Fi",
    pinned_dns_ips: Optional[List[str]] = None,
    timeout_seconds: int = 900,
) -> Dict[str, Any]:
    """
    Enforces RBAC (blocks VIEWER) and applies scoped firewall containment.
    """
    if user_role.upper() == "VIEWER":
        raise PermissionError("Role 'VIEWER' is not authorized to initiate network quarantine.")

    session_id = f"nti-q-{uuid.uuid4().hex[:8]}"
    now_utc = datetime.now(timezone.utc)
    expires_at = now_utc + timedelta(seconds=timeout_seconds)

    # Apply via authoritative Windows Agent manager
    agent_result = apply_scoped_firewall_quarantine(
        session_id=session_id,
        target_interface=target_interface,
        pinned_dns_ips=pinned_dns_ips,
        timeout_seconds=timeout_seconds,
        reason=reason,
    )

    # Persist in Database
    session_record = NetworkQuarantineSession(
        id=session_id,
        organization_id=organization_id,
        user_id=user_id,
        host_id=host_id,
        target_interface=target_interface,
        isolation_level="BALANCED_QUARANTINE",
        applied_rules=agent_result.get("rules_applied", []),
        trigger_reason=reason,
        risk_score=risk_score,
        timeout_seconds=timeout_seconds,
        expires_at=expires_at,
        status="ACTIVE" if agent_result.get("status") in ("ACTIVE", "MOCK_ACTIVE") else "ELEVATION_REQUIRED",
    )
    db.add(session_record)

    # Create Audit Log entry
    audit = AuditLog(
        organization_id=organization_id,
        actor_user_id=user_id,
        actor_role=user_role,
        event_category="NETWORK_TRUST",
        action="NETWORK_QUARANTINE_APPLIED",
        resource_type="NETWORK_QUARANTINE_SESSION",
        resource_id=session_id,
        metadata_json={
            "host_id": host_id,
            "target_interface": target_interface,
            "risk_score": risk_score,
            "reason": reason,
            "status": session_record.status,
            "rules_count": len(agent_result.get("rules_applied", [])),
        },
    )
    db.add(audit)
    db.commit()

    return {
        "session_id": session_id,
        "status": session_record.status,
        "host_id": host_id,
        "target_interface": target_interface,
        "rules_applied": agent_result.get("rules_applied", []),
        "expires_at": expires_at.isoformat(),
        "timeout_seconds": timeout_seconds,
        "message": agent_result.get("message", "Quarantine rules successfully applied to wireless interface."),
    }


def release_network_quarantine(
    db: Session,
    session_id: Optional[str] = None,
    user_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    user_role: str = "ADMIN",
) -> Dict[str, Any]:
    """
    Enforces RBAC (blocks VIEWER) and rolls back all active quarantine rules.
    """
    if user_role.upper() == "VIEWER":
        raise PermissionError("Role 'VIEWER' is not authorized to release network quarantine.")

    agent_result = rollback_firewall_quarantine()
    now_utc = datetime.now(timezone.utc)

    # Update database sessions
    query = db.query(NetworkQuarantineSession).filter(NetworkQuarantineSession.status == "ACTIVE")
    if session_id:
        query = query.filter(NetworkQuarantineSession.id == session_id)
    if organization_id:
        query = query.filter(NetworkQuarantineSession.organization_id == organization_id)

    active_sessions = query.all()
    for s in active_sessions:
        s.status = "ROLLED_BACK"
        s.released_by = user_id or "ADMIN"
        s.released_at = now_utc

    # Create Audit Log entry
    audit = AuditLog(
        organization_id=organization_id,
        actor_user_id=user_id,
        actor_role=user_role,
        event_category="NETWORK_TRUST",
        action="NETWORK_QUARANTINE_RELEASED",
        resource_type="NETWORK_QUARANTINE_SESSION",
        resource_id=session_id or "ALL_ACTIVE",
        metadata_json={
            "released_by": user_id,
            "released_at": now_utc.isoformat(),
            "active_sessions_cleared": len(active_sessions),
        },
    )
    db.add(audit)
    db.commit()

    return {
        "status": "ROLLED_BACK",
        "released_sessions_count": len(active_sessions),
        "released_at": now_utc.isoformat(),
        "message": "Quarantine rules rolled back cleanly. Network access restored.",
    }


def get_active_quarantine_status(
    db: Session,
    host_id: Optional[str] = None,
    organization_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Queries both the database ledger and local disk state for active containment."""
    disk_state = read_quarantine_state()

    query = db.query(NetworkQuarantineSession).filter(NetworkQuarantineSession.status == "ACTIVE")
    if host_id:
        query = query.filter(NetworkQuarantineSession.host_id == host_id)
    if organization_id:
        query = query.filter(NetworkQuarantineSession.organization_id == organization_id)

    active_session = query.order_by(NetworkQuarantineSession.created_at.desc()).first()

    is_active = bool(active_session or (disk_state and disk_state.get("status") == "ACTIVE"))
    return {
        "is_quarantined": is_active,
        "active_session": {
            "session_id": active_session.id if active_session else (disk_state.get("session_id") if disk_state else None),
            "target_interface": active_session.target_interface if active_session else (disk_state.get("target_interface", "Wi-Fi") if disk_state else "Wi-Fi"),
            "trigger_reason": active_session.trigger_reason if active_session else (disk_state.get("reason") if disk_state else None),
            "risk_score": active_session.risk_score if active_session else 0,
            "expires_at": active_session.expires_at.isoformat() if active_session else (disk_state.get("expires_at") if disk_state else None),
            "rules_applied": active_session.applied_rules if active_session else (disk_state.get("rules_applied", []) if disk_state else []),
        } if is_active else None,
        "is_elevated_admin": is_elevated_admin(),
    }
