import re

from openclaw_governance_proxy.policy import CompiledRule, evaluate_policy, is_text_like


def rule(**kw):
    return CompiledRule(id="r1", name="r1", severity="critical", action="block", direction="both", match_type="regex", scope="global", agent_id=None, policy_mode=None, tags=(), patterns=("ignore previous",), domains=(), content_types=(), regexes=(re.compile("ignore previous"),)) 


def test_rule_matching():
    matches = evaluate_policy([rule()], direction="request", host="x", url="https://x", body="ignore previous")
    assert matches and matches[0].action == "block"


def test_url_query_values_are_inspected():
    matches = evaluate_policy([rule()], direction="request", host="example.com", url="https://example.com/?q=ignore%20previous")
    assert matches and matches[0].matched == "ignore previous"


def test_encoded_body_values_are_inspected():
    matches = evaluate_policy([rule()], direction="request", host="chatgpt.com", url="wss://chatgpt.com/ws", body="Open https://example.com/?q=ignore%20previous")
    assert matches and matches[0].matched == "ignore previous"


def test_double_encoded_body_values_are_inspected():
    matches = evaluate_policy([rule()], direction="request", host="chatgpt.com", url="wss://chatgpt.com/ws", body="Open https://example.com/?q=ignore%2520previous")
    assert matches and matches[0].matched == "ignore previous"


def test_text_like_content_types():
    assert is_text_like("application/json")
    assert is_text_like("text/html")
    assert not is_text_like("image/png")
