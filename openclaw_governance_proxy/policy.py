from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

from .agent_policy import action_for_policy, effective_rules
from .redaction import contains_secret
from .rules import CompiledRule


@dataclass
class Match:
    rule: CompiledRule
    action: str
    matched: str


TEXT_CONTENT_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
    "application/javascript",
    "application/x-www-form-urlencoded",
)


def is_text_like(content_type: str | None) -> bool:
    value = (content_type or "").split(";")[0].strip().lower()
    return value.startswith("text/") or value in TEXT_CONTENT_TYPES


def matches_domain(rule: CompiledRule, host: str) -> str | None:
    host = (host or "").lower().strip(".")
    for domain in rule.domains:
        d = domain.lower().strip(".")
        if host == d or host.endswith("." + d):
            return domain
    return None


def evaluate_text(rule: CompiledRule, text: str) -> str | None:
    inspection_text = text or ""
    decoded_variants = [inspection_text]
    current = inspection_text
    for _ in range(4):
        decoded = unquote(current)
        if decoded == current:
            break
        decoded_variants.append(decoded)
        current = decoded
    combined_text = "\n".join(decoded_variants)
    if rule.match_type == "regex":
        for regex in rule.regexes:
            m = regex.search(combined_text)
            if m:
                return m.group(0)[:160]
    if rule.match_type in {"keyword", "header", "url", "json_key"}:
        lower = combined_text.lower()
        for pattern in rule.patterns:
            if pattern.lower() in lower:
                return pattern[:160]
    if rule.match_type == "secret_detector" and contains_secret(text or ""):
        return "secret_detector"
    return None


def url_inspection_text(url: str) -> str:
    """Return URL text plus decoded query names and values for policy matching."""
    try:
        parts = urlsplit(url)
        query_parts = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            query_parts.append(key)
            query_parts.append(value)
        decoded_url = unquote(unquote(url))
        return "\n".join([url, decoded_url, unquote(unquote(parts.path)), unquote(unquote(parts.query)), *query_parts])
    except Exception:
        return url


def evaluate_policy(
    rules: list[CompiledRule],
    *,
    direction: str,
    host: str,
    url: str,
    method: str = "",
    headers: dict | None = None,
    body: str = "",
    content_type: str = "",
    agent_id: str | None = None,
    agent_tags: set[str] | None = None,
    policy_mode: str = "balanced",
) -> list[Match]:
    tags = agent_tags or set()
    text_headers = json.dumps(headers or {}, sort_keys=True)
    inspection_text = "\n".join([method, url_inspection_text(url), host, text_headers, body or ""])
    matches: list[Match] = []
    for rule in effective_rules(rules, agent_id, tags, policy_mode):
        if rule.direction not in {direction, "both"}:
            continue
        if rule.content_types and content_type and not any(content_type.startswith(ct) for ct in rule.content_types):
            continue
        matched = matches_domain(rule, host) if rule.match_type == "domain" else evaluate_text(rule, inspection_text)
        if matched:
            matches.append(Match(rule=rule, action=action_for_policy(rule, policy_mode), matched=matched))
    return matches


def strongest_match(matches: list[Match]) -> Match | None:
    priority = {"block": 4, "redact": 3, "warn": 2, "monitor": 1}
    return sorted(matches, key=lambda m: priority.get(m.action, 0), reverse=True)[0] if matches else None
