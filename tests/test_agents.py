from openclaw_governance_proxy.agent_identity import hash_agent_token, verify_agent_token


def test_agent_token_hashing():
    token_hash = hash_agent_token("secret-token")
    assert "secret-token" not in token_hash
    assert verify_agent_token(token_hash, "secret-token")
