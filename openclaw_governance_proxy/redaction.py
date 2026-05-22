from __future__ import annotations

import re

REDACTION = "[REDACTED_BY_GOVERNANCE]"
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}

SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|password|secret|token)\s*[:=]\s*['\"]?[^'\"\s,;]{6,}"),
    re.compile(r"(?i)bearer\s+[a-zA-Z0-9._\-]{20,}"),
    re.compile(r"-----BEGIN\s+(RSA|OPENSSH|PRIVATE)\s+KEY-----[\s\S]+?-----END\s+\1\s+KEY-----"),
    re.compile(r"(?i)aws_(access_key_id|secret_access_key)\s*[:=]\s*[A-Z0-9/+=]{16,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]+"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]+"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    re.compile(r"(?i)(postgresql|mysql|mongodb(?:\+srv)?)://[^\s]+"),
]


def redact_text(text: str) -> str:
    result = text or ""
    for pattern in SECRET_PATTERNS:
        result = pattern.sub(REDACTION, result)
    return result


def redact_headers(headers: dict | None) -> dict:
    safe = {}
    for key, value in (headers or {}).items():
        if key.lower() in SENSITIVE_HEADERS or re.search(r"(?i)(token|secret|password|key|cookie)", key):
            safe[key] = REDACTION
        else:
            safe[key] = str(value)[:512]
    return safe


def contains_secret(text: str) -> bool:
    return any(pattern.search(text or "") for pattern in SECRET_PATTERNS)
