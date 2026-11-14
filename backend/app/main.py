"""
MYX AI (Windows Edition) — FastAPI Backend Entry Point.
Brand: MYX AI by Midhun Krishnan ("Discover. Detect. Defend.")
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.brand import (
    BRAND_AUTHOR,
    BRAND_EDITION_NAME,
    BRAND_FULL_TITLE,
    BRAND_PRODUCT_NAME,
    BRAND_TAGLINE,
    BRAND_VERSION,
)
from app.core.config import settings
from app.database.init_db import init_database_and_seeds
from app.routers.assessments import (
    router as assessments_router,
    IN_MEMORY_TARGETS,
    IN_MEMORY_ASSESSMENTS,
    IN_MEMORY_FINDINGS,
)

app = FastAPI(
    title=f"{BRAND_FULL_TITLE} ({BRAND_EDITION_NAME}) API",
    description=f"{BRAND_TAGLINE} — Defensive Cybersecurity Assessment, Windows 10/11 System Auditing & AI Security Intelligence API",
    version=BRAND_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.include_router(assessments_router)

@app.on_event("startup")
def on_startup():
    init_database_and_seeds()

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
)


_SETTINGS_STATE = {
    "themeMode": "dark",
    "labTargetsAllowed": True,
    "timeoutSec": 10,
    "maxRedirects": 5,
    "maxConcurrentScans": 3,
}


@app.get("/api/v1/health", tags=["Health & Brand"])
def health_check():
    return {
        "status": "ok",
        "product": BRAND_PRODUCT_NAME,
        "edition": BRAND_EDITION_NAME,
        "brand": BRAND_FULL_TITLE,
        "author": BRAND_AUTHOR,
        "tagline": BRAND_TAGLINE,
        "version": BRAND_VERSION,
        "mode": "LIVE_FASTAPI",
        "supported_local_os": ["Windows 10 (20H2+)", "Windows 11 (21H2-24H2+)"],
        "database": "sqlite_connected" if "sqlite" in settings.DATABASE_URL else "postgres_connected",
        "gemini_configured": bool(settings.GEMINI_API_KEY or settings.GEMINI_API_KEY_2),
        "ai_failover_configured": bool(settings.GEMINI_API_KEY_2 or settings.GROQ_API_KEY),
        "ai_providers_active": [
            *(["gemini_primary"] if settings.GEMINI_API_KEY else []),
            *(["gemini_backup"] if settings.GEMINI_API_KEY_2 else []),
            *(["groq_backup"] if settings.GROQ_API_KEY else []),
        ],
    }


@app.get("/api/v1/settings", tags=["Platform Settings & Theme"])
def get_platform_settings():
    return _SETTINGS_STATE


@app.patch("/api/v1/settings", tags=["Platform Settings & Theme"])
def update_platform_settings(payload: dict):
    if payload.get("themeMode") in ("dark", "light"):
        _SETTINGS_STATE["themeMode"] = payload["themeMode"]
    if isinstance(payload.get("labTargetsAllowed"), bool):
        _SETTINGS_STATE["labTargetsAllowed"] = payload["labTargetsAllowed"]
    if isinstance(payload.get("timeoutSec"), int):
        _SETTINGS_STATE["timeoutSec"] = max(2, min(30, payload["timeoutSec"]))
    if isinstance(payload.get("maxRedirects"), int):
        _SETTINGS_STATE["maxRedirects"] = max(0, min(5, payload["maxRedirects"]))
    if isinstance(payload.get("maxConcurrentScans"), int):
        _SETTINGS_STATE["maxConcurrentScans"] = max(1, min(10, payload["maxConcurrentScans"]))
    return {"settings": _SETTINGS_STATE}


@app.get("/api/v1/bootstrap", tags=["Bootstrap State"])
def get_bootstrap_state():
    return {
        "settings": _SETTINGS_STATE,
        "targets": IN_MEMORY_TARGETS,
        "assessments": IN_MEMORY_ASSESSMENTS,
        "windowsAgents": [],
        "windowsInventoryByAgent": {},
        "windowsPostureByAgent": {},
        "windowsSockets": [],
        "wifiNetworks": [],
        "findings": IN_MEMORY_FINDINGS,
        "aiSessions": [],
        "ragDocuments": [],
        "reports": [],
        "externalImports": [],
        "integrations": [],
        "orgUsers": [],
        "auditLogs": [],
    }


