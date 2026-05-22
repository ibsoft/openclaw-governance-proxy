from __future__ import annotations

import hashlib
import html
import json
import re
import secrets
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

HEADER_VALUE_RE = re.compile(r"[\r\n]")


def utciso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_header_value(value: object, max_len: int = 512) -> str:
    """Return a header-safe value with CR/LF stripped to prevent response splitting."""
    text = "" if value is None else str(value)
    text = HEADER_VALUE_RE.sub(" ", text).strip()
    return text[:max_len]


def body_hash16(data: bytes | str | None) -> str:
    if data is None:
        data = b""
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()[:16]


def json_dumps_safe(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, default=str)


def load_json_list(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def redact_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        safe_q = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            if re.search(r"(?i)(token|secret|key|password|auth|cookie|session)", key):
                safe_q.append((key, "[REDACTED]"))
            else:
                safe_q.append((key, value[:128]))
        return urlunsplit((parts.scheme, parts.netloc, parts.path[:512], urlencode(safe_q), ""))
    except Exception:
        return "[INVALID_URL]"


def escape_snippet(value: str, limit: int = 300) -> str:
    return html.escape((value or "")[:limit])
