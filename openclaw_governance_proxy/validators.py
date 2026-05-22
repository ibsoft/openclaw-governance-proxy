from __future__ import annotations

import ipaddress
import re

VALID_ACTIONS = {"monitor", "warn", "redact", "block"}
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_DIRECTIONS = {"request", "response", "both"}
VALID_MATCH_TYPES = {"regex", "keyword", "domain", "header", "url", "json_key", "secret_detector"}
VALID_SCOPES = {"global", "agent", "tag", "policy_mode"}
RULE_ID_RE = re.compile(r"^[a-z0-9_-]+$")
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?$")


def validate_rule_id(rule_id: str) -> bool:
    return bool(rule_id and RULE_ID_RE.fullmatch(rule_id))


def validate_domain(domain: str) -> bool:
    if not domain:
        return False
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return bool(HOST_RE.fullmatch(domain.strip(".")))


def compile_regex(pattern: str):
    return re.compile(pattern)


def validate_password(username: str, email: str, password: str) -> tuple[bool, str]:
    weak = {"password", "password123456789", "adminadminadmin", "openclawpassword"}
    if len(password or "") < 15:
        return False, "Password must be at least 15 characters."
    if len(password) > 256:
        return False, "Password is too long."
    lowered = password.lower()
    if lowered in weak:
        return False, "Password is too common."
    if username and lowered == username.lower():
        return False, "Password cannot equal username."
    if username and username.lower() in lowered:
        return False, "Password cannot contain username."
    local = (email or "").split("@")[0]
    if local and local.lower() in lowered:
        return False, "Password cannot contain email local part."
    return True, ""
