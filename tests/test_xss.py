from openclaw_governance_proxy.utils import escape_snippet


def test_xss_escaping():
    assert "&lt;script&gt;" in escape_snippet("<script>alert(1)</script>")
