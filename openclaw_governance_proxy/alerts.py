from __future__ import annotations

from .database import db
from .models import Alert


def create_alert(severity: str, title: str, message: str) -> None:
    db.session.add(Alert(severity=severity, title=title, message=message))
    db.session.commit()
