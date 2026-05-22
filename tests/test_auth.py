from openclaw_governance_proxy.validators import validate_password


def test_password_policy():
    assert not validate_password("alice", "alice@example.com", "short")[0]
    assert not validate_password("alice", "alice@example.com", "alice-password-long-enough")[0]
    assert validate_password("alice", "alice@example.com", "A-very-long-secure-passphrase-2026")[0]
