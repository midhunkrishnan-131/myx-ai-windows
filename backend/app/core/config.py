"""
Pydantic BaseSettings configuration for MYX AI (Windows Edition) FastAPI backend.
"""
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_ENV: str = "development"
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    CORS_ALLOWED_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173"

    DATABASE_URL: str = "sqlite:///./myx_local_test.db"
    ENCRYPTION_MASTER_KEY: str = "7m6Q5v8X2p4R9k3L1n8B0z5C4v7N6m2Q8w4E1r9T3y5="

    SESSION_COOKIE_NAME: str = "myx_session"
    SESSION_COOKIE_SECURE: bool = False
    SESSION_TTL_HOURS: int = 24
    CSRF_SECRET_KEY: str = "dev-csrf-secret-change-in-production"

    ALLOW_CONTROLLED_LAB_TARGETS: bool = False
    OUTBOUND_HTTP_TIMEOUT_SECONDS: int = 10
    OUTBOUND_HTTP_MAX_REDIRECTS: int = 5
    OUTBOUND_HTTP_MAX_BYTES: int = 5_242_880
    MAX_SCANNER_UPLOAD_MB: int = 25

    GEMINI_API_KEY: str = ""
    GEMINI_API_KEY_2: str = ""
    GROQ_API_KEY: str = ""
    GEMINI_PRIMARY_MODEL: str = "gemini-2.5-flash"
    GEMINI_ADVANCED_MODEL: str = "gemini-2.5-pro"
    GEMINI_FAST_MODEL: str = "gemini-2.5-flash-lite"
    GEMINI_EMBEDDING_MODEL: str = "gemini-embedding-001"

    RESEND_API_KEY: str = ""
    RESEND_FROM_EMAIL: str = "security-noreply@myx-security.io"

    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    URLHAUS_AUTH_KEY: str = ""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ALLOWED_ORIGINS.split(",") if o.strip()]


settings = Settings()
