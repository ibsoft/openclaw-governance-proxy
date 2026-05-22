from openclaw_governance_proxy.addon import bounded_text


def test_bounded_text_keeps_tail():
    text = "A" * 100 + "ignore%20previous%20instructions"
    sampled = bounded_text(text, 80)
    assert "OPENCLAW_GOVERNANCE_TRUNCATED_MIDDLE" in sampled
    assert "ignore%20previous%20instructions" in sampled


def test_bounded_text_short_value_unchanged():
    assert bounded_text("hello", 40) == "hello"
