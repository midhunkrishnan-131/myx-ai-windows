# MYX AI (Windows Edition)

**Brand Presentation:** MYX AI by Midhun Krishnan  
**Tagline:** *Discover. Detect. Defend.*  
**Category:** AI-Powered Cybersecurity Assessment, Vulnerability Management, Windows 10/11 System Auditing & Security Intelligence SaaS Platform

---

## 1. Product Overview

**MYX AI (Windows Edition)** empowers authorized security analysts, system administrators, and engineering teams to assess their own websites, networks, Wi-Fi environments, and Microsoft Windows 10/11 endpoints, identify security weaknesses with verifiable technical evidence, manage vulnerability lifecycles with deterministic CVSS v3.1 scoring, query a tenant-isolated PostgreSQL `pgvector` RAG AI Security Analyst, import third-party scanner outputs (`defusedxml` hardened), and publish human-approved executive and technical security reports.

---

## 2. Technology Stack

- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS, Lucide React (`lucide-react`), Recharts (`recharts`), React Router (`react-router-dom`)
- **Backend:** Python 3.11+, FastAPI, Pydantic v2, SQLAlchemy 2.0 (31 normalized tables), Alembic, Argon2-CFFI (`argon2-cffi`), PyOTP (`pyotp`) + `qrcode`, Official Google GenAI SDK (`google-genai`), `defusedxml`, `httpx`, `dnspython`, `reportlab`, `python-docx`, `pytest`
- **Database:** PostgreSQL 15+ (Neon Serverless PostgreSQL, Supabase PostgreSQL, or local PostgreSQL) with `pgvector` (`Vector(768)`)
- **Local Security Agent:** Standalone Python 3.11+ package (`windows_agent/`) supporting **Microsoft Windows 10 (20H2+)** and **Microsoft Windows 11 (21H2–24H2+)** exclusively

---

## 3. Repository Structure

```text
myx-ai-windows-edition/
├── README.md                          # Complete setup, architecture, Windows agent & deployment guide
├── PROJECT_STATUS.md                  # Matrix of completed, scaffolded, and runtime-dependent features
├── ARCHITECTURE.md                    # System design, security boundaries, SSRF/RAG/TOTP data flows
├── API_INTEGRATION.md                 # Complete Frontend-to-Backend REST API contract specification
├── ANTIGRAVITY_HANDOFF.md             # Step-by-step developer playbook for Google Antigravity IDE
├── src/                               # Modular React + TypeScript Frontend
│   ├── config/                        # brand.config.ts & env.config.ts
│   ├── types/                         # Strictly typed domain contracts
│   ├── services/                      # apiClient.ts + 11 domain API services
│   ├── context/                       # AuthContext.tsx & SystemStatusContext.tsx
│   ├── hooks/                         # useAuth.ts, useRBAC.ts, useApiQuery.ts
│   ├── utils/                         # Pure defensive security logic & unit tests (securityLogic.test.ts)
│   ├── components/                    # Reusable UI primitives, layout shell, & RBAC guards
│   └── pages/                         # All 17 primary navigation views + AuthPortalPage
├── backend/                           # FastAPI + SQLAlchemy 2.0 + Alembic Backend
│   ├── .env.example
│   ├── requirements.txt
│   ├── alembic.ini
│   ├── pytest.ini
│   ├── app/
│   │   ├── main.py
│   │   ├── core/                      # brand.py, config.py
│   │   ├── database/                  # session.py
│   │   ├── models/                    # domain_models.py (31 normalized tables)
│   │   ├── auth/                      # password.py (Argon2id), totp.py (RFC 6238 + replay guard)
│   │   ├── security/                  # ssrf_guard.py, file_validator.py (defusedxml)
│   │   └── ai/                        # gemini_client.py (google-genai model router & schema guard)
│   └── tests/                         # Pytest suite (Auth, TOTP, RBAC, SSRF, Parsers, AI/RAG)
└── windows_agent/                     # Standalone Windows 10/11 Local Security Auditing Agent
    ├── README_AGENT.md
    ├── requirements.txt
    ├── agent_config.example.json
    ├── myx_windows_agent.py
    └── collectors/                    # system_info.py, security_posture.py, network_diag.py, wifi_auditor.py
```

---

## 4. Quick Setup in VS Code / Google Antigravity (Windows PowerShell)

### Frontend Setup
```powershell
npm install
npm run dev
# Frontend runs at http://localhost:3000
# Run frontend security logic unit tests:
npx --yes tsx --test src/utils/securityLogic.test.ts
```

### FastAPI Backend Setup
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
# Edit .env with your DATABASE_URL, ENCRYPTION_MASTER_KEY, and GEMINI_API_KEY
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Run Backend Pytest Security Suite
```powershell
cd backend
pytest
```
