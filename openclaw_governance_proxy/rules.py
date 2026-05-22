from __future__ import annotations

import json
import re
from dataclasses import dataclass

import yaml

from .database import db
from .models import Rule, RuleChangeHistory
from .utils import json_dumps_safe, load_json_list
from .validators import (
    VALID_ACTIONS,
    VALID_DIRECTIONS,
    VALID_MATCH_TYPES,
    VALID_SCOPES,
    VALID_SEVERITIES,
    compile_regex,
    validate_domain,
    validate_rule_id,
)


@dataclass(frozen=True)
class CompiledRule:
    id: str
    name: str
    severity: str
    action: str
    direction: str
    match_type: str
    scope: str
    agent_id: str | None
    policy_mode: str | None
    tags: tuple[str, ...]
    patterns: tuple[str, ...]
    domains: tuple[str, ...]
    content_types: tuple[str, ...]
    regexes: tuple[re.Pattern, ...]


def rule_to_dict(rule: Rule) -> dict:
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "enabled": rule.enabled,
        "severity": rule.severity,
        "action": rule.action,
        "direction": rule.direction,
        "match_type": rule.match_type,
        "scope": rule.scope,
        "agent_id": rule.agent_id,
        "policy_mode": rule.policy_mode,
        "patterns": load_json_list(rule.patterns),
        "domains": load_json_list(rule.domains),
        "content_types": load_json_list(rule.content_types),
        "tags": load_json_list(rule.tags),
        "notes": rule.notes,
    }


def validate_rule_payload(data: dict, existing_id: str | None = None) -> tuple[bool, str]:
    rule_id = data.get("id") or existing_id
    if not validate_rule_id(rule_id):
        return False, "Rule ID must contain lowercase letters, numbers, hyphen, or underscore."
    for field, allowed in {
        "severity": VALID_SEVERITIES,
        "action": VALID_ACTIONS,
        "direction": VALID_DIRECTIONS,
        "match_type": VALID_MATCH_TYPES,
        "scope": VALID_SCOPES,
    }.items():
        if data.get(field) not in allowed:
            return False, f"Invalid {field}."
    patterns = data.get("patterns") or []
    domains = data.get("domains") or []
    if data.get("match_type") == "regex":
        for pattern in patterns:
            try:
                compile_regex(pattern)
            except re.error as exc:
                return False, f"Invalid regex {pattern}: {exc}"
    for domain in domains:
        if not validate_domain(domain):
            return False, f"Invalid domain: {domain}"
    return True, ""


def compile_rule(rule: Rule) -> CompiledRule:
    patterns = tuple(load_json_list(rule.patterns))
    regexes = tuple(re.compile(p) for p in patterns) if rule.match_type == "regex" else ()
    return CompiledRule(
        id=rule.id,
        name=rule.name,
        severity=rule.severity,
        action=rule.action,
        direction=rule.direction,
        match_type=rule.match_type,
        scope=rule.scope,
        agent_id=rule.agent_id,
        policy_mode=rule.policy_mode,
        tags=tuple(load_json_list(rule.tags)),
        patterns=patterns,
        domains=tuple(load_json_list(rule.domains)),
        content_types=tuple(load_json_list(rule.content_types)),
        regexes=regexes,
    )


def load_active_rules(session) -> list[CompiledRule]:
    rules = session.query(Rule).filter(Rule.enabled.is_(True), Rule.deleted_at.is_(None)).all()
    compiled: list[CompiledRule] = []
    errors: list[str] = []
    for rule in rules:
        try:
            compiled.append(compile_rule(rule))
            if rule.compile_error:
                rule.compile_error = None
        except Exception as exc:
            rule.compile_error = str(exc)
            errors.append(f"{rule.id}: {exc}")
    if errors:
        session.commit()
        raise RuntimeError("Rule compile errors: " + "; ".join(errors))
    return compiled


def audit_rule_change(rule_id: str, actor, action: str, old: dict | None, new: dict | None, source_ip: str = "", user_agent: str = "") -> None:
    db.session.add(
        RuleChangeHistory(
            rule_id=rule_id,
            actor_user_id=getattr(actor, "id", None),
            actor_username=getattr(actor, "username", "system"),
            action=action,
            old_value_json=json_dumps_safe(old or {}),
            new_value_json=json_dumps_safe(new or {}),
            source_ip=source_ip,
            user_agent=user_agent[:512],
        )
    )


def seed_rules_from_yaml(path: str, actor: str = "system") -> int:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    count = 0
    for item in data.get("rules", []):
        payload = {
            **item,
            "patterns": item.get("patterns") or [],
            "domains": item.get("domains") or [],
            "content_types": item.get("content_types") or [],
            "tags": item.get("tags") or [],
        }
        ok, msg = validate_rule_payload(payload)
        if not ok:
            raise ValueError(msg)
        if Rule.query.get(payload["id"]):
            continue
        rule = Rule(
            id=payload["id"],
            name=payload["name"],
            description=payload.get("description", ""),
            enabled=payload.get("enabled", True),
            severity=payload["severity"],
            action=payload["action"],
            direction=payload["direction"],
            match_type=payload["match_type"],
            scope=payload.get("scope", "global"),
            policy_mode=payload.get("policy_mode"),
            agent_id=payload.get("agent_id"),
            patterns=json.dumps(payload["patterns"]),
            domains=json.dumps(payload["domains"]),
            content_types=json.dumps(payload["content_types"]),
            tags=json.dumps(payload["tags"]),
            notes=payload.get("notes", ""),
            created_by=actor,
            updated_by=actor,
        )
        db.session.add(rule)
        count += 1
    db.session.commit()
    return count


def export_rules_yaml() -> str:
    rules = Rule.query.filter(Rule.deleted_at.is_(None)).order_by(Rule.id).all()
    return yaml.safe_dump({"rules": [rule_to_dict(r) for r in rules]}, sort_keys=False)
