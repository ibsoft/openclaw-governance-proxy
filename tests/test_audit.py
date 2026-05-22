from openclaw_governance_proxy.redaction import redact_text


def test_audit_logging_does_not_include_secrets():
    assert "supersecret" not in redact_text("token=supersecret")
