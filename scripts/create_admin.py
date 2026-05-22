#!/usr/bin/env python
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from openclaw_governance_proxy.app import app
from openclaw_governance_proxy.auth import create_user, hash_password
from openclaw_governance_proxy.database import db
from openclaw_governance_proxy.models import User
from openclaw_governance_proxy.validators import validate_password


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--init-db-only", action="store_true")
    parser.add_argument("--reset-password", action="store_true", help="Reset password for an existing admin username")
    parser.add_argument("--list-users", action="store_true", help="List local users without sensitive fields")
    args = parser.parse_args()
    with app.app_context():
        if args.init_db_only:
            print("Database initialized")
            return
        if args.list_users:
            for user in User.query.order_by(User.id).all():
                print(f"id={user.id} username={user.username} email={user.email} role={user.role} enabled={user.enabled}")
            return
        username = input("Admin username or email: ")
        existing = User.query.filter_by(username=username).first() or User.query.filter_by(email=username).first()
        if args.reset_password:
            if not existing:
                raise SystemExit(f"No user named {username!r} exists")
            password = getpass.getpass("New password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                raise SystemExit("Passwords do not match")
            ok, message = validate_password(existing.username, existing.email, password)
            if not ok:
                raise SystemExit(message)
            existing.password_hash = hash_password(password)
            existing.session_version += 1
            existing.enabled = True
            existing.role = "admin"
            db.session.commit()
            print("Admin password reset")
            return

        if existing:
            raise SystemExit(
                f"User {username!r} already exists. Use scripts/create_admin.py --reset-password to set a new password."
            )
        email = input("Admin email: ")
        if User.query.filter_by(email=email).first():
            raise SystemExit(
                f"Email {email!r} already exists. Login with the existing account or use --reset-password with its username."
            )
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            raise SystemExit("Passwords do not match")
        create_user(username, email, password, "admin")
        print("Admin created")


if __name__ == "__main__":
    main()
