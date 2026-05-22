import re

from openclaw_governance_proxy.agent_policy import action_for_policy, effective_rules
from openclaw_governance_proxy.rules import CompiledRule


def cr(id, scope="global", tags=(), agent_id=None):
    return CompiledRule(id=id, name=id, severity="high", action="block", direction="both", match_type="regex", scope=scope, agent_id=agent_id, policy_mode=None, tags=tags, patterns=("x",), domains=(), content_types=(), regexes=(re.compile("x"),))


def test_agent_specific_policy_resolution():
    rules = effective_rules([cr("g"), cr("a", scope="agent", agent_id="agent1")], "agent1", set(), "balanced")
    assert [r.id for r in rules] == ["a", "g"]


def test_tag_based_policy_resolution():
    rules = effective_rules([cr("g"), cr("t", scope="tag", tags=("prod",))], None, {"prod"}, "balanced")
    assert [r.id for r in rules] == ["t", "g"]


def test_monitor_rule_is_not_escalated_by_policy_mode():
    rule = cr("secret_detector")
    object.__setattr__(rule, "severity", "critical")
    object.__setattr__(rule, "action", "monitor")
    assert action_for_policy(rule, "balanced") == "monitor"
    assert action_for_policy(rule, "strict") == "monitor"


def test_balanced_mode_preserves_explicit_high_block_rules():
    rule = cr("suspicious_exfil_destinations")
    assert action_for_policy(rule, "balanced") == "block"
