from openclaw_governance_proxy.utils import safe_header_value


def test_crlf_header_injection_prevented():
    assert "\r" not in safe_header_value("test\r\nX-Evil: injected")
    assert "\n" not in safe_header_value("test\nSet-Cookie: hacked=true")
