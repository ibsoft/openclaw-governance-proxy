from openclaw_governance_proxy.validators import validate_domain, validate_rule_id
from openclaw_governance_proxy.rules import validate_rule_payload


def test_invalid_regex_rejection():
    ok, _ = validate_rule_payload({"id": "x", "severity": "high", "action": "block", "direction": "both", "match_type": "regex", "scope": "global", "patterns": ["["]})
    assert not ok


def test_domain_validation():
    assert validate_domain("example.com")
    assert validate_domain("169.254.169.254")
    assert not validate_domain("bad host")
    assert validate_rule_id("good_rule-1")
