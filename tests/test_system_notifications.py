from openclaw_governance_proxy.system_notifications import _RECENT_NOTIFICATIONS, enabled_from_settings, recently_notified, severity_allowed


def test_desktop_notifications_disabled_by_default(monkeypatch):
    monkeypatch.delenv("OPENCLAW_DESKTOP_NOTIFICATIONS", raising=False)
    assert not enabled_from_settings({})


def test_desktop_notifications_env_override(monkeypatch):
    monkeypatch.setenv("OPENCLAW_DESKTOP_NOTIFICATIONS", "true")
    assert enabled_from_settings({"desktop_notifications_enabled": "false"})


def test_desktop_notification_severity_threshold():
    assert severity_allowed("critical", "high")
    assert severity_allowed("high", "high")
    assert not severity_allowed("medium", "high")


def test_notification_dedupe_window():
    _RECENT_NOTIFICATIONS.clear()
    assert not recently_notified("r1", "example.com", "block", 10)
    assert recently_notified("r1", "example.com", "block", 10)
    assert not recently_notified("r2", "example.com", "block", 10)
