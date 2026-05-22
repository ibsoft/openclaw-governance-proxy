from openclaw_governance_proxy.redaction import REDACTION, redact_headers, redact_text


def test_redaction():
    assert REDACTION in redact_text("password=supersecret")
    assert redact_headers({"Authorization": "Bearer abc"})["Authorization"] == REDACTION
