from __future__ import annotations

from functools import wraps

from flask import abort
from flask_login import current_user, login_required


def roles_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        @login_required
        def inner(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                abort(403)
            return fn(*args, **kwargs)

        return inner

    return wrapper


admin_required = roles_required("admin")
auditor_or_admin = roles_required("admin", "auditor")
viewer_allowed = roles_required("admin", "auditor", "viewer")
