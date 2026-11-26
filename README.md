# MYX AI (Windows Edition)

[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)

**MYX AI by Midhun Krishnan** — *Discover. Detect. Defend.*  
Version **2.4.0-WIN**.

MYX AI is a local security-assessment console for teams who already have permission to test their own websites, networks, and Windows 10/11 machines. Analysts register authorized targets, review evidence, track findings, and draft reports. An optional FastAPI service adds header scoring, hybrid retrieval for the analyst copilot, and PDF export. A separate Windows agent collects read-only posture from a Windows 10 or 11 host.

The repository does not include a license file.

## Who it is for

The console has three roles:

| Role | What they can do |
| --- | --- |
| `ADMIN` | Manage users, targets, settings, and report approval |
| `SECURITY_ANALYST` | Run assessments, triage findings, and use the AI analyst |
| `VIEWER` | Read dashboards, history, and reports |

Self-service registration can create a `SECURITY_ANALYST` or a `VIEWER`. It cannot create an `ADMIN`. The first administrator is created at startup.

## What you can do

These behaviors are implemented in `server.ts`, `src/`, or `backend/`.

- **Sign in and sessions.** Registration, login, logout, forgot-password, reset-password, and password rotation. Passwords on the integrated server are stored with scrypt. Login attempts are rate-limited. Session cookies are checked against a server-side store, and state-changing `/api/v1` requests require the session CSRF token.
- **Authorized targets.** Analysts register a target and verify it with a DNS TXT record, an HTTP challenge, or an administrator lab approval. The SSRF guard rejects loopback, cloud metadata addresses, non-HTTP schemes, and private addresses unless lab mode and an administrator approval are both set.
- **Website assessment.** Scores nine HTTP controls (CSP, HSTS, clickjacking defense, cookie flags, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, server banner, and HTTPS redirection). The weights sum to 100. The integrated server forwards a scan to FastAPI when that process is up, and otherwise runs its own engine.
- **Network assessment.** TCP checks against a registered host, with a built-in port catalog and optional custom ports.
- **Findings.** Status changes, assignment, comments, and an audit trail for analyst and admin roles.
- **History and reports.** Assessment history, a comparison of two runs, a reports list, and admin approval before a report is marked ready to publish. FastAPI builds assessment PDFs with ReportLab.
- **AI Security Analyst and Report Studio.** With `GEMINI_API_KEY` set, the integrated server calls the Google GenAI SDK, then `GEMINI_API_KEY_2`, then Groq when `GROQ_API_KEY` is set. FastAPI exposes `/api/v1/ai/copilot/chat`, `/explain-finding`, and `/executive-summary`. That copilot classifies intent, searches with BM25, merges rankings, reranks, and keeps conversation memory. Those retrieval steps run without an API key. Chunk embeddings are stored as JSON on `rag_document_chunks.embedding_json`.
- **LinkGuard.** Lexical URL checks (including punycode and homograph signals). When `VIRUSTOTAL_API_KEY` or `GOOGLE_SAFE_BROWSING_API_KEY` is set, the integrated server can add those lookups.
- **Wi-Fi Password Lab.** On Windows, lists saved WLAN profiles with `netsh`, can read a saved key locally on demand, scores a passphrase offline, generates a passphrase, and exports a PDF that redacts passwords. Saved keys are not written to the database.
- **Windows agent.** `windows_agent/` collects system inventory, security posture, network diagnostics, and WLAN data on Windows 10 (20H2+) and Windows 11 (21H2 through 24H2+). Collectors are read-only. There is no remote-shell command in the agent.

### Screens that are still preview data

- **SSL/TLS Analyzer** copies the bundled sample result and substitutes the hostname and port you type. It does not open a TLS socket.
- **DNS Analyzer** parses SPF and DMARC text you paste. The rest of that page is the bundled sample, including DNSSEC.
- **Account Security** can rotate a password through `POST /api/v1/auth/rotate-password` from other clients. The form on that page updates local state. TOTP enrollment calls `/api/v1/auth/2fa/setup` and `/api/v1/auth/2fa/confirm`, which the integrated server does not implement, so the client falls back to preview data. `POST /api/v1/auth/verify-2fa` checks that a code is at least six characters and does not validate an authenticator secret. RFC 6238 helpers live in `backend/app/auth/totp.py` and are covered by pytest. They are not mounted on a FastAPI route.
- **Scanner import on the integrated server** stores an import record. It does not parse the file. The parser that does run is `backend/app/security/file_validator.py`: Burp XML, Nmap XML, Nessus (`.nessus`), and ZAP or Nikto JSON, via `defusedxml`, with a 25 MB cap.
- **Integrations.** Saving a provider secret keeps a masked suffix in memory. The connectivity action updates that in-memory status. `RESEND_API_KEY` and `URLHAUS_AUTH_KEY` are accepted by FastAPI settings and shown in the UI. No client in this repo calls Resend or URLhaus.
- **Windows agent `enroll`** prints the server URL and exits. It does not send the token.

The Settings page can point the UI at three transports: the integrated API on the same origin, FastAPI at `http://127.0.0.1:8000`, or an offline sandbox that skips health checks.

## Tech stack

| Layer | What the repo uses |
| --- | --- |
| UI | React 19, TypeScript, Vite 8, Tailwind CSS 4, React Router 7, Recharts, Lucide, Motion |
| Integrated server | Node.js, Express 4, Vite middleware in development, static `dist/` in production |
| API service | Python, FastAPI, Uvicorn, Pydantic v2, SQLAlchemy 2 |
| Database | SQLite by default. `DATABASE_URL` can point at PostgreSQL. `psycopg` and `pgvector` are dependencies. There is no migration that creates a `pgvector` column. |
| Documents | ReportLab PDFs, `python-docx` |
| AI SDKs | `@google/genai` on the Node server, `google-genai` on FastAPI |
| Tests | `node:test` for `src/utils`, pytest for `backend/tests` |

`alembic` is installed and `backend/alembic.ini` points at `migrations/`. That directory is not in the repository. Schema creation is `Base.metadata.create_all` when FastAPI starts (31 tables in `backend/app/models/domain_models.py`).

## Prerequisites

- Node.js 22.13 or newer and npm 10. The Rolldown binding in the lockfile also accepts Node.js 20.19. Verified with Node.js 22.23.4 and npm 10.9.9.
- Python 3.11 or newer for the FastAPI service and the Windows agent. Verified with Python 3.12.3.
- A Windows 10 or Windows 11 machine to run the local agent collectors. On Linux the agent starts and reports that the OS is unsupported.

PostgreSQL is optional. Gemini, Groq, VirusTotal, and Google Safe Browsing are optional.

## Installation

From the repository root:

```bash
npm ci
```

`@rolldown/binding-win32-x64-msvc` is an optional dependency. `npm ci` skips it on Linux and macOS and installs it on 64-bit Windows.

FastAPI, from `backend/`:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Windows PowerShell equivalent for the virtualenv (not executed in the Linux verification of this README):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Windows agent dependencies, on a Windows host, from `windows_agent/`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

`pywin32` and `wmi` are marked for Windows only. On Linux, `pip install -r windows_agent/requirements.txt` installs `psutil` and `httpx` and skips those two packages. That was verified. The collectors still require Windows.

## Configuration

Copy the example files and set values on your machine. The names below are the ones the code reads. This README does not include values.

```bash
cp .env.example .env
cp backend/.env.example backend/.env
```

The integrated server loads `.env` from the repository root, then loads `backend/.env` for any name that is still unset. Vite reads `VITE_*` from the root `.env`. FastAPI reads `backend/.env` when you start Uvicorn from the `backend/` directory.

| Name | Process |
| --- | --- |
| `FRONTEND_PORT` | Integrated server listen port |
| `NODE_ENV` | Development uses Vite middleware. Production serves `dist/` |
| `TRUST_PROXY` | Trust the reverse-proxy hop |
| `COOKIE_SECURE` | Mark the session cookie Secure |
| `CORS_ALLOWED_ORIGINS` | Comma-separated browser origins |
| `ADMIN_BOOTSTRAP_EMAIL` | First administrator email on the integrated server |
| `ADMIN_BOOTSTRAP_PASSWORD` | First administrator password on the integrated server |
| `ADMIN_INITIAL_PASSWORD` | Alternate bootstrap password. FastAPI's seeder reads this name |
| `GEMINI_API_KEY` | Primary Gemini key |
| `GEMINI_API_KEY_2` | Second Gemini key |
| `GROQ_API_KEY` | Groq failover key |
| `GEMINI_PRIMARY_MODEL` | FastAPI primary model name |
| `GEMINI_ADVANCED_MODEL` | FastAPI advanced model name |
| `GEMINI_FAST_MODEL` | FastAPI fast model name |
| `GEMINI_EMBEDDING_MODEL` | FastAPI embedding model name |
| `VIRUSTOTAL_API_KEY` | Optional LinkGuard lookup |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Optional LinkGuard lookup |
| `VITE_API_BASE_URL` | Optional UI API origin. Blank uses the same origin |
| `VITE_APP_ENV` | UI environment label |
| `DISABLE_HMR` | Turn off Vite HMR and file watching |
| `APP_ENV` | FastAPI environment label |
| `HOST` | Loaded by FastAPI settings. The start command below passes the bind address on the CLI |
| `PORT` | Loaded by FastAPI settings. The start command below passes the port on the CLI |
| `DATABASE_URL` | FastAPI database URL. Unset uses the SQLite file under `backend/runtime/` |
| `ENCRYPTION_MASTER_KEY` | FastAPI key for secrets at rest. Unset uses a development default in code. Set this before any shared deployment |
| `SESSION_COOKIE_NAME` | FastAPI session cookie name |
| `SESSION_COOKIE_SECURE` | FastAPI Secure cookie flag |
| `SESSION_TTL_HOURS` | FastAPI session lifetime |
| `CSRF_SECRET_KEY` | FastAPI CSRF secret |
| `ALLOW_CONTROLLED_LAB_TARGETS` | FastAPI lab-target policy |
| `OUTBOUND_HTTP_TIMEOUT_SECONDS` | FastAPI outbound HTTP timeout |
| `OUTBOUND_HTTP_MAX_REDIRECTS` | FastAPI redirect cap |
| `OUTBOUND_HTTP_MAX_BYTES` | FastAPI response size cap |
| `MAX_SCANNER_UPLOAD_MB` | FastAPI scanner upload cap |
| `RESEND_API_KEY` | Accepted by FastAPI settings. No mail client calls it |
| `RESEND_FROM_EMAIL` | Accepted by FastAPI settings |
| `URLHAUS_AUTH_KEY` | Accepted by FastAPI settings. No client calls it |

If `ADMIN_BOOTSTRAP_PASSWORD` and `ADMIN_INITIAL_PASSWORD` are both unset, the integrated server generates a one-time administrator password and prints it once. The same happens in FastAPI for `ADMIN_INITIAL_PASSWORD`. If `ADMIN_BOOTSTRAP_EMAIL` is unset, the integrated server uses the address compiled into `server.ts`.

Runtime accounts, sessions, and the SQLite file are written under `backend/runtime/`. That directory is gitignored.

## Run and build

Integrated UI and API, development:

```bash
npm run dev
```

Verified: the process listens on `http://127.0.0.1:3000` (or `FRONTEND_PORT`). `GET /api/v1/health` returns `mode: LIVE_BACKEND`. `/` and `/login` return the Vite app.

Production, after a build:

```bash
npm run build
NODE_ENV=production npm start
```

Verified: `/` is served from `dist/`, and `GET /api/v1/health` still returns `LIVE_BACKEND`. `/login` and `/dashboard` fall through to `index.html`.

`npm run preview` serves the static build only. A request to `/api/v1/health` on that port returns `index.html`, not JSON. Use `npm start` with `NODE_ENV=production` when you want the API and the built UI together.

`npm run lint` is `tsc --noEmit`. Verified clean.

FastAPI, from `backend/` with the virtualenv active:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Verified: startup creates the SQLite schema, `GET /api/v1/health` returns `mode: LIVE_FASTAPI` and `database: sqlite_connected`, and `/api/docs`, `/api/redoc`, and `/openapi.json` respond.

`alembic upgrade head` fails because `backend/migrations` does not exist. Use the startup `create_all` path above.

On Windows, set the production mode in PowerShell with `$env:NODE_ENV = "production"` before `npm start`. That shell was not available in the Linux verification.

## Usage

Open the console:

```text
http://127.0.0.1:3000/login
```

Health check, no session required:

```bash
curl -s http://127.0.0.1:3000/api/v1/health
```

Create an analyst or viewer at `/register`. The integrated server requires a password of at least 10 characters with an uppercase letter, a lowercase letter, a digit, and a symbol.

After sign-in the home route sends you to `/dashboard`. The sidebar is the catalog in `src/components/layout/navigationCatalog.ts`:

| Group | Screens |
| --- | --- |
| Core & Posture | Dashboard, Assessment History |
| Assessments & Auditors | Website Assessment, Network Assessment, Wi-Fi Security Auditor, Wi-Fi Password Lab, Windows Security Auditor |
| Intelligence & Analyzers | LinkGuard AI, SSL/TLS Analyzer, DNS Analyzer |
| Findings & AI Copilot | Vulnerability Findings, AI Security Analyst, AI Report Studio, Reports |
| Administration & Account | Integrations, User Management (admin), Settings, Account Security |

To use FastAPI from the UI, start Uvicorn, then on Settings choose **External FastAPI Server**. Interactive API docs:

```text
http://127.0.0.1:8000/api/docs
```

Windows agent, on Windows 10 or 11, from `windows_agent/`:

```powershell
python myx_windows_agent.py audit
python myx_windows_agent.py enroll --server http://127.0.0.1:8000 --token <one-time-token>
```

On Linux, `audit` prints `UNSUPPORTED_OS` and the detected platform. `enroll` prints a line and does not contact the server. Both of those Linux outcomes were verified. The PowerShell collector run was not.

## Tests

UI logic:

```bash
npx tsx --test src/utils/securityLogic.test.ts src/utils/securityMaster.test.ts
```

Verified: 25 tests passed.

FastAPI, from `backend/` with the virtualenv active:

```bash
pytest
```

Verified: 40 tests passed.

## Project structure

```text
.
├── server.ts                  # Express API, sessions, and Vite or dist/
├── index.html
├── package.json
├── vite.config.ts
├── tsconfig.json
├── .env.example               # Integrated server and Vite names
├── src/                       # React console
│   ├── pages/                 # Auth portal and console screens
│   ├── components/            # Shell, navigation, shared UI
│   ├── services/              # API client and domain calls
│   ├── context/               # Auth and system status
│   ├── hooks/
│   ├── utils/                 # securityLogic.ts and node:test files
│   ├── types/
│   ├── config/                # Brand and env
│   └── data/                  # Preview records used when a route is missing
├── public/                    # Brand mark and a static HTML write-up
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI entry
│   │   ├── routers/           # Assessments, AI copilot, Wi-Fi lab
│   │   ├── services/          # Scoring, retrieval, PDFs, Wi-Fi
│   │   ├── models/            # 31 SQLAlchemy tables
│   │   ├── auth/              # Argon2id and TOTP helpers
│   │   ├── security/          # SSRF guard and scanner upload parser
│   │   └── database/          # Engine and create_all seed
│   ├── tests/
│   ├── requirements.txt
│   ├── alembic.ini
│   └── .env.example
├── windows_agent/             # Windows 10/11 collectors
│   ├── myx_windows_agent.py
│   ├── collectors/
│   └── README_AGENT.md
└── frontend/                  # Brand config copy only. The UI is src/
```

Design notes that already live in the repo: `ARCHITECTURE.md`, `API_INTEGRATION.md`, `API_SECURITY_MATRIX.md`, `AUTHENTICATION_ARCHITECTURE.md`, `PROJECT_STATUS.md`, and `windows_agent/README_AGENT.md`, plus the security and deployment checklists. Where one of those notes disagrees with a path above, follow the code this README describes.

There is no screenshot or demo recording in the repository. The brand mark is `public/assets/aistudio/MYX-AI-primary-vertical-2048x1818-transparent_803e553e.png`.

## Contributing

Issues and pull requests are welcome.

- Branch from `main` and describe the behavior you changed.
- Do not commit `.env`, `backend/.env`, `backend/runtime/`, database files, or one-time passwords printed at startup.
- Before you open a PR, run `npm run lint`, the `node:test` command above, and `pytest` in `backend/`.
- Agent collector changes need a Windows 10 or Windows 11 host. Linux can only confirm the unsupported-OS path.

This repository does not currently include a license file. Ask the maintainer before redistributing it.
