"""
Database initialization and default enterprise seed provisioning.
Creates all 31 normalized SQLAlchemy tables and inserts system roles, organization,
and default administrator account.
"""
from app.database.session import engine, SessionLocal
from app.models.domain_models import Base, Role, Permission, RolePermission, Organization, User, OrganizationMembership
from app.auth.password import hash_password_argon2id


def init_database_and_seeds():
    print("[MYX AI Database] Creating all 31 normalized schema tables...")
    Base.metadata.create_all(bind=engine)
    print("[MYX AI Database] Tables created or verified.")

    db = SessionLocal()
    try:
        # 1. System Roles
        roles_data = [
            ("ADMIN", "Full organizational administrative control over users, targets, integrations, and scans."),
            ("SECURITY_ANALYST", "Security operations role to execute scans, triage findings, and query AI Security Analyst."),
            ("VIEWER", "Read-only compliance and reporting viewer role."),
        ]
        role_map = {}
        for name, desc in roles_data:
            existing = db.query(Role).filter(Role.name == name).first()
            if not existing:
                role = Role(name=name, description=desc, is_system_role=True)
                db.add(role)
                db.flush()
                role_map[name] = role
            else:
                role_map[name] = existing

        # 2. Default Organization
        org = db.query(Organization).filter(Organization.slug == "myx-defense-ops").first()
        if not org:
            org = Organization(
                name="MYX Defense Operations Lab",
                slug="myx-defense-ops",
                lab_targets_allowed=True,
                default_scan_rate_limit=60,
            )
            db.add(org)
            db.flush()
            print(f"[MYX AI Database] Provisioned default organization: {org.name} ({org.slug})")

        # 3. Default Admin User (Secure Bootstrap - Never overwrite existing credentials)
        admin_email = "midhun.krishnan@myx-security.io"
        admin_user = db.query(User).filter(User.email == admin_email).first()
        if not admin_user:
            import secrets
            initial_admin_pass = os.getenv("ADMIN_INITIAL_PASSWORD")
            if not initial_admin_pass:
                initial_admin_pass = secrets.token_urlsafe(18)
                print(f"[SECURITY ALERT] Initial Administrator Provisioned. One-time bootstrap password: {initial_admin_pass}")
            admin_user = User(
                email=admin_email,
                password_hash=hash_password_argon2id(initial_admin_pass),
                full_name="Midhun Krishnan",
                job_title="Principal Security Architect",
                is_active=True,
                is_email_verified=True,
            )
            db.add(admin_user)
            db.flush()
        # Existing admin user credentials are strictly preserved and never overwritten

        # 4. Membership
        existing_membership = db.query(OrganizationMembership).filter(
            OrganizationMembership.organization_id == org.id,
            OrganizationMembership.user_id == admin_user.id
        ).first()
        if not existing_membership:
            membership = OrganizationMembership(
                organization_id=org.id,
                user_id=admin_user.id,
                role_id=role_map["ADMIN"].id,
                is_primary=True,
            )
            db.add(membership)
            print(f"[MYX AI Database] Provisioned default administrator: {admin_email} (Role: ADMIN)")

        db.commit()
        print("[MYX AI Database] Database initialization & seeding completed successfully!")
    except Exception as e:
        db.rollback()
        print(f"[MYX AI Database] Seeding error: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    init_database_and_seeds()
