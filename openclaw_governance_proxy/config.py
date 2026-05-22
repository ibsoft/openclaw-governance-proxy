from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
CONFIG_DIR = BASE_DIR / "config"

load_dotenv(BASE_DIR / ".env")


def resolve_db_path() -> Path:
    configured = Path(os.getenv("OPENCLAW_DB_PATH", str(DATA_DIR / "governance.db"))).expanduser()
    if not configured.is_absolute():
        configured = BASE_DIR / configured
    return configured.resolve()


def database_uri() -> str:
    configured_url = os.getenv("OPENCLAW_DATABASE_URL") or os.getenv("DATABASE_URL")
    if configured_url:
        if configured_url.startswith("postgres://"):
            configured_url = "postgresql://" + configured_url.removeprefix("postgres://")
        return configured_url
    return "sqlite:///" + str(resolve_db_path())


def sqlalchemy_engine_options(uri: str) -> dict:
    if uri.startswith("sqlite:"):
        return {"connect_args": {"check_same_thread": False, "timeout": 5}}
    return {"pool_pre_ping": True}


class Config:
    SECRET_KEY = os.getenv("OPENCLAW_SECRET_KEY") or secrets.token_urlsafe(48)
    SQLALCHEMY_DATABASE_URI = database_uri()
    SQLALCHEMY_ENGINE_OPTIONS = sqlalchemy_engine_options(SQLALCHEMY_DATABASE_URI)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_TIME_LIMIT = None
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("OPENCLAW_SESSION_COOKIE_SECURE", "false").lower() == "true"
    REMEMBER_COOKIE_DURATION = 0
    PERMANENT_SESSION_LIFETIME = int(os.getenv("OPENCLAW_SESSION_SECONDS", "3600"))
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024
    RATELIMIT_STORAGE_URI = "memory://"
    UI_HOST = os.getenv("OPENCLAW_UI_HOST", "127.0.0.1")
    UI_PORT = int(os.getenv("OPENCLAW_UI_PORT", "8899"))
    PROXY_HOST = os.getenv("OPENCLAW_PROXY_HOST", "127.0.0.1")
    PROXY_PORT = int(os.getenv("OPENCLAW_PROXY_PORT", "8888"))


DEFAULT_SETTINGS = {
    "policy_mode": "balanced",
    "max_inspect_body_size": "65536",
    "log_retention_days": "30",
    "proxy_host": "127.0.0.1",
    "proxy_port": "8888",
    "ui_host": "127.0.0.1",
    "ui_port": "8899",
    "inspect_responses": "true",
    "inspect_requests": "true",
    "domain_blocking": "true",
    "secret_detection": "true",
    "block_unknown_agents": "false",
    "agent_token_required": "false",
    "desktop_notifications_enabled": "false",
    "desktop_notifications_min_severity": "high",
    "desktop_notifications_dedupe_seconds": "10",
    "rule_cache_ttl": "5",
    "database_busy_timeout": "5000",
    "session_lifetime": "3600",
}
