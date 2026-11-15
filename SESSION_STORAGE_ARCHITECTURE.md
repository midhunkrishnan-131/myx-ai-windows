# MYX AI (Windows Edition) — Persistent & Scalable Session Storage Architecture

**Application:** MYX AI by Midhun Krishnan  
**Classification:** BACKEND PERSISTENCE & SESSION ARCHITECTURE  
**Status:** **IMPLEMENTED & VERIFIED** (Disk-backed atomic persistence active; multi-instance tested)  
**Date:** November 15, 2026  

---

## 1. Architectural Overview & Objectives

In prior prototypes, session state resided solely within an ephemeral JavaScript `Map` in memory. This introduced two critical production limitations:
1. **Server Restart Fragility:** Restarting or updating the server immediately logged out all active users.
2. **Horizontal Scaling Blockers:** Multiple load-balanced backend processes could not validate sessions created by another instance.

To eliminate these vulnerabilities, MYX AI implements a **dual-tiered, persistent, atomic session architecture**:
- **L1 In-Memory Cache:** Provides microsecond token verification for active requests.
- **L2 Persistent Disk Store:** Persists session records to an atomic, versioned file store in `backend/runtime/sessions.json` (untracked, excluded from Git).
- **Relational Enterprise Model:** Integrated with SQLAlchemy 2.0 `UserSession` table in PostgreSQL / SQLite (`backend/app/models/domain_models.py`).

```
+-----------------------------------------------------------------------------------------+
|                                  AUTHENTICATED REQUEST                                  |
|                                                                                         |
|                       Client supplies HttpOnly cookie: myx_session                      |
+--------------------------------------------+--------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
|                        SESSION RESOLVER: getSessionByToken(rawToken)                    |
|                                                                                         |
|   1. Compute: tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex')    |
|                                                                                         |
|   2. Check L1 Cache (activeSessions Map) ────► [ HIT ] ────► Validate Timestamps        |
|                       │                                                │                |
|                    [ MISS ]                                            │                |
|                       ▼                                                │                |
|   3. Read L2 Persistent Store (backend/runtime/sessions.json)          │                |
|       (Enables cross-process / multi-instance validation)              │                |
|                       │                                                │                |
|                 [ Found on Disk ]                                      │                |
|                       ▼                                                │                |
|   4. Populate L1 Cache with Session Record                             │                |
|                                                                        │                |
|   5. Validate Session Validity:                                        │                |
|       - !session.revokedAt                                             │                |
|       - now < session.expiresAt (24h Max TTL)                          │                |
|       - now - session.lastActiveAt <= SESSION_IDLE_TIMEOUT_MS (2h)     │                |
|                                                                        │                |
|   6. Sliding Idle Timeout Refresh:                                     │                |
|       - session.lastActiveAt = now                                     │                |
|       - Throttled atomic disk sync (every 15s)                         │                |
|                                                                        ▼                |
|                                                          HTTP Request Authorized        |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Cryptographic Storage & Threat Model

### Protection Against Database Snapshot Compromise
The raw session token (a 32-byte hexadecimal CSPRNG string) is **never persisted to disk or the database**.

Only the SHA-256 cryptographic digest is stored:
$$\text{tokenHash} = \text{SHA-256}(\text{rawToken})$$

If an attacker gains read access to the persistent session file or database dump, they cannot reverse the SHA-256 hash to recreate valid session cookies or impersonate users.

### Stored Record Schema:
```json
{
  "id": "sess-8a7f1c9d2e4b6a0f",
  "tokenHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "userId": "usr-admin-01",
  "user": {
    "id": "usr-admin-01",
    "email": "midhun.krishnan@myx-security.io",
    "role": "ADMIN",
    "is_active": true
  },
  "csrfToken": "1c7a9b3d5f8e02416a9d2c4e6b8f0a12",
  "createdAt": 1731670000000,
  "expiresAt": 1731756400000,
  "lastActiveAt": 1731671500000,
  "ip": "127.0.0.1",
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
  "revokedAt": null
}
```

---

## 3. Session Lifetimes & Eviction Policies

1. **Absolute Maximum Expiration (TTL):** 24 hours (`SESSION_TTL_MS = 86,400,000 ms`). After 24 hours, the session expires unconditionally, requiring re-authentication.
2. **Sliding Inactivity Timeout:** 2 hours (`SESSION_IDLE_TIMEOUT_MS = 7,200,000 ms`). Each request updates `lastActiveAt`. If a user is inactive for more than 2 hours, the session is invalidated.
3. **Atomic File Write Strategy:**
   Disk updates use a temporary file write followed by an atomic rename:
   ```ts
   const tmpPath = `${SESSIONS_DB_PATH}.tmp.${Date.now()}`;
   fs.writeFileSync(tmpPath, JSON.stringify(array, null, 2), 'utf-8');
   fs.renameSync(tmpPath, SESSIONS_DB_PATH);
   ```
   This guarantees that power outages, OS crashes, or concurrent reads never encounter a corrupted or partially written JSON file.

---

## 4. Session Invalidation Triggers

The architecture supports both single-session and global account-wide revocation:

| Action | Function Called | Scope | Outcome |
|:---|:---|:---:|:---|
| User clicks **Logout** | `destroySessionByToken(token)` | Single Session | Marks `revokedAt = now`, deletes session from L1 and L2, clears client cookie. |
| User **Rotates Password** | `revokeAllSessionsForUser(userId)` | All Devices | Invalidates all existing sessions for that user across all browsers. Issues 1 fresh session for the active client. |
| Password **Reset via Token** | `revokeAllSessionsForUser(userId)` | All Devices | Invalidates all existing sessions. User must sign in fresh with new password. |
| Admin **Deactivates Account** | `revokeAllSessionsForUser(userId)` | All Devices | Immediately terminates all active sessions. Subsequent requests return HTTP 401 (`ACCOUNT_DEACTIVATED`). |
| Admin **Changes User Role** | `revokeAllSessionsForUser(userId)` | All Devices | Forces user to re-authenticate so their session token receives updated RBAC claims. |

---

## 5. SQLAlchemy 2.0 Relational Model (`backend/app/`)

For deployments using PostgreSQL (Supabase, Neon, AWS RDS) or dedicated SQLite, the relational model is declared in `backend/app/models/domain_models.py`:

```python
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
```

### Database Migration & Rollback Commands:
```bash
# 1. Apply schema migration to PostgreSQL/SQLite
alembic upgrade head

# 2. Rollback migration if necessary
alembic downgrade -1
```

---

## 6. Verification Test Results

Automated unit and integration tests in `src/utils/securityMaster.test.ts` verify persistent sessions:
1. `Security Phase 4: Persistent Session Storage Survives Process Restart` (**PASSED**)
2. `Security Phase 4: Multi-Instance Session Revocation on Account Deactivation` (**PASSED**)
