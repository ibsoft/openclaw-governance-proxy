from __future__ import annotations

from .rules import CompiledRule

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def action_for_policy(rule: CompiledRule, policy_mode: str) -> str:
    if rule.action == "monitor":
        return "monitor"
    if policy_mode == "monitor_only":
        return "monitor"
    if policy_mode == "assessment_mode":
        if rule.severity in {"critical"} or "secret" in rule.id or "metadata" in rule.id or "private-key" in rule.id:
            return "block"
        return "monitor"
    if policy_mode == "strict" and SEVERITY_ORDER.get(rule.severity, 0) >= 3:
        return "block"
    if policy_mode == "balanced" and rule.severity == "critical":
        return "block"
    return rule.action


def effective_rules(all_rules: list[CompiledRule], agent_id: str | None, tags: set[str], policy_mode: str) -> list[CompiledRule]:
    emergency = [r for r in all_rules if r.scope == "global" and r.severity == "critical" and r.action == "block"]
    agent_rules = [r for r in all_rules if r.scope == "agent" and r.agent_id == agent_id]
    tag_rules = [r for r in all_rules if r.scope == "tag" and set(r.tags) & tags]
    global_rules = [r for r in all_rules if r.scope == "global" and r not in emergency]
    mode_rules = [r for r in all_rules if r.scope == "policy_mode" and r.policy_mode == policy_mode]
    ordered = emergency + agent_rules + tag_rules + global_rules + mode_rules
    seen = set()
    result = []
    for rule in ordered:
        if rule.id not in seen:
            seen.add(rule.id)
            result.append(rule)
    return result
