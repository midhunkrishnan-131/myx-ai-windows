# PROJECT STATUS MATRIX — MYX AI (WINDOWS EDITION)

**Brand:** MYX AI by Midhun Krishnan ("Discover. Detect. Defend.")

This matrix provides an honest, transparent accounting of every module generated in **Google AI Studio (Build Mode)** and what requires live runtime execution in **Google Antigravity**.

| # | Module / Feature | Status Classification | Notes |
| :- | :--- | :--- | :--- |
| 1 | **Brand & Design System (`#0B1120` / `#080D1A` / `#131C31`)** | `[COMPLETED IN AI STUDIO]` | Centralized in `src/config/brand.config.ts` and `backend/app/core/brand.py`. |
| 2 | **Responsive 17-View React Shell & Navigation** | `[COMPLETED IN AI STUDIO]` | Tested across mobile (`390×844`) and desktop (`1440×900`) viewports with RBAC guards. |
| 3 | **Honest-State Connection Banner (`DEMO / SAMPLE DATA — BACKEND NOT CONNECTED`)** | `[COMPLETED IN AI STUDIO]` | Automatically checks `http://127.0.0.1:8000/api/v1/health` and displays transparent preview mode when offline. |
| 4 | **Pure Security Logic & Unit Tests (`securityLogic.test.ts`)** | `[COMPLETED IN AI STUDIO]` | SSRF/RFC1918/Cloud Metadata guard, LinkGuard Punycode/lexical analyzer, CVSS v3.1 calculator, SPF/DMARC parser, and RBAC matrix verified via `node:test`. |
| 5 | **31 Normalized SQLAlchemy 2.0 ORM Models (`domain_models.py`)** | `[COMPLETED IN AI STUDIO]` | Full schema defined in `backend/app/models/domain_models.py`. |
| 6 | **Argon2id Hashing, RFC 6238 TOTP & Replay Guard (`backend/app/auth/`)** | `[COMPLETED IN AI STUDIO]` | Implemented in `password.py` and `totp.py` with `pytest` coverage. |
| 7 | **PostgreSQL 15+ & `pgvector` Database Migrations** | `[SCAFFOLDED — REQUIRES BACKEND RUNTIME IN ANTIGRAVITY]` | Run `alembic upgrade head` against Neon, Supabase, or local PostgreSQL in Google Antigravity. |
| 8 | **Live Outbound HTTP/TLS/DNS/TCP Socket Scanners** | `[SCAFFOLDED — REQUIRES BACKEND RUNTIME IN ANTIGRAVITY]` | `ssrf_guard.py` implemented; execute live network checks from FastAPI worker in Antigravity. |
| 9 | **Windows 10/11 Local Security Agent (`windows_agent/`)** | `[REQUIRES WINDOWS 10/11 AGENT ENROLLMENT]` | Standalone Python collectors (`system_info.py`, `security_posture.py`, `network_diag.py`, `wifi_auditor.py`) ready to run on Windows 10/11 hosts. |
| 10 | **Google Gemini API (`google-genai`) & RAG Embeddings** | `[REQUIRES EXTERNAL API KEY]` | Configure `GEMINI_API_KEY` in `backend/.env` in Google Antigravity. |
| 11 | **Resend Email, Safe Browsing v4, VirusTotal v3, URLhaus** | `[REQUIRES EXTERNAL API KEY]` | Configure keys in `backend/.env` and verify via `/integrations` connectivity checks. |
