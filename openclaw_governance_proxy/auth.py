from __future__ import annotations

from datetime import datetime, timedelta, timezone

from flask import request, session
from flask_login import LoginManager
from werkzeug.security import check_password_hash, generate_password_hash

from .database import db
from .models import LoginAttempt, User
from .validators import validate_password

login_manager = LoginManager()
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


def hash_password(password: str) -> str:
    return generate_password_hash(password, method="scrypt")


def check_password(user: User, password: str) -> bool:
    return check_password_hash(user.password_hash, password)


def create_user(username: str, email: str, password: str, role: str = "viewer") -> User:
    ok, msg = validate_password(username, email, password)
    if not ok:
        raise ValueError(msg)
    user = User(username=username, email=email, role=role, password_hash=hash_password(password))
    db.session.add(user)
    db.session.commit()
    return user


def record_login_attempt(username: str, success: bool) -> None:
    db.session.add(LoginAttempt(username=username[:80], source_ip=request.remote_addr or "", success=success))
    db.session.commit()


def too_many_login_attempts(username: str) -> bool:
    since = datetime.now(timezone.utc) - timedelta(minutes=10)
    ip_count = LoginAttempt.query.filter(LoginAttempt.source_ip == (request.remote_addr or ""), LoginAttempt.created_at >= since, LoginAttempt.success.is_(False)).count()
    account_count = LoginAttempt.query.filter(LoginAttempt.username == username, LoginAttempt.created_at >= since, LoginAttempt.success.is_(False)).count()
    return ip_count >= 5 or account_count >= 10


def regenerate_session() -> None:
    session.clear()
    session.permanent = True
