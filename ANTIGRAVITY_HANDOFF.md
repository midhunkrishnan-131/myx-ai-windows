# GOOGLE ANTIGRAVITY HANDOFF PLAYBOOK (`ANTIGRAVITY_HANDOFF.md`)

**Product:** MYX AI (Windows Edition) — *MYX AI by Midhun Krishnan ("Discover. Detect. Defend.")*

---

## 1. Post-Export Checklist (Google AI Studio → Google Antigravity)

1. **Clone / Open Repository in Google Antigravity IDE** on a Windows 10 or Windows 11 development workstation.
2. **Verify Frontend Build & Unit Tests:**
   ```powershell
   npm install
   npx --yes tsx --test src/utils/securityLogic.test.ts
   npm run build
   ```
3. **Initialize Python 3.11+ Virtual Environment & Backend Dependencies:**
   ```powershell
   cd backend
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
4. **Configure `backend/.env`:**
   - Copy `backend/.env.example` to `backend/.env`.
   - Provision a PostgreSQL 15+ instance (Neon Serverless PostgreSQL, Supabase PostgreSQL, or local PostgreSQL) and enable `CREATE EXTENSION IF NOT EXISTS vector;`.
   - Generate a Fernet master key:
     ```powershell
     python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
     ```
   - Set `GEMINI_API_KEY` from Google AI Studio.
5. **Run Backend Pytest Suite:**
   ```powershell
   cd backend
   .\.venv\Scripts\python -m pytest
   ```
6. **Start FastAPI Server & Switch Frontend from Preview Mode to Live Mode:**
   ```powershell
   cd backend
   .\.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```
   Once FastAPI is listening on `http://127.0.0.1:8000`, click **"Retry FastAPI Check"** in the top banner of the React UI (`http://localhost:3000`). The banner automatically transitions from `DEMO / SAMPLE DATA — BACKEND NOT CONNECTED` to `LIVE FASTAPI BACKEND CONNECTED`.
