from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import unquote, urlparse
from typing import Iterator

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import scoped_session, sessionmaker

from .config import Config, DATA_DIR, DEFAULT_SETTINGS, LOG_DIR

db = SQLAlchemy(session_options={"expire_on_commit": False})
SessionLocal: scoped_session | None = None


@event.listens_for(Engine, "connect")
def set_sqlite_pragmas(dbapi_connection, connection_record) -> None:
    if not isinstance(dbapi_connection, sqlite3.Connection):
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def init_app_db(app) -> None:
    global SessionLocal
    DATA_DIR.mkdir(exist_ok=True)
    LOG_DIR.mkdir(exist_ok=True)
    sqlite_path = sqlite_file_path(app.config["SQLALCHEMY_DATABASE_URI"])
    if sqlite_path:
        sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    db.init_app(app)
    with app.app_context():
        from . import models  # noqa: F401

        db.create_all()
        seed_settings()
        engine = db.engine
        SessionLocal = scoped_session(sessionmaker(bind=engine, expire_on_commit=False))


@contextmanager
def session_scope() -> Iterator:
    """Provide a short-lived SQLAlchemy session safe for threaded hooks."""
    if SessionLocal is None:
        from sqlalchemy import create_engine

        uri = Config.SQLALCHEMY_DATABASE_URI
        engine = create_engine(uri, **engine_options(uri))
        local = scoped_session(sessionmaker(bind=engine, expire_on_commit=False))
    else:
        local = SessionLocal
    session = local()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def seed_settings() -> None:
    from .models import Setting

    for key, value in DEFAULT_SETTINGS.items():
        if not db.session.get(Setting, key):
            db.session.add(Setting(key=key, value=value))
    db.session.commit()


def sqlite_wal_enabled() -> bool:
    if urlparse(Config.SQLALCHEMY_DATABASE_URI).scheme != "sqlite":
        return False
    with session_scope() as session:
        row = session.execute(text("PRAGMA journal_mode")).scalar()
        return str(row).lower() == "wal"


def check_file_permissions(path: str | Path) -> bool:
    p = Path(path)
    return not p.exists() or (p.stat().st_mode & 0o077) == 0


def sqlite_file_path(uri: str) -> Path | None:
    parsed = urlparse(uri)
    if parsed.scheme != "sqlite" or parsed.path in {"", ":memory:"}:
        return None
    return Path(unquote(parsed.path))


def engine_options(uri: str) -> dict:
    parsed = urlparse(uri)
    if parsed.scheme == "sqlite":
        return {"connect_args": {"check_same_thread": False, "timeout": 5}}
    return {"pool_pre_ping": True}
