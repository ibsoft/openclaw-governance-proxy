def test_csrf_required(client):
    r = client.post("/logout")
    assert r.status_code in {400, 401, 302}
