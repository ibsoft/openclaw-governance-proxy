from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import threading
import time

from .logging_jsonl import write_jsonl
from .config import LOG_DIR

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_RECENT_NOTIFICATIONS: dict[str, float] = {}
_RECENT_LOCK = threading.Lock()


def enabled_from_settings(settings: dict[str, str]) -> bool:
    env_value = os.getenv("OPENCLAW_DESKTOP_NOTIFICATIONS", "").lower()
    if env_value in {"1", "true", "yes", "on"}:
        return True
    if env_value in {"0", "false", "no", "off"}:
        return False
    return settings.get("desktop_notifications_enabled", "false").lower() == "true"


def severity_allowed(severity: str, min_severity: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(min_severity, 3)


def notify_governance_event(settings: dict[str, str], *, rule_id: str, severity: str, host: str, action: str, event_id: int, request_id: str) -> None:
    """Send a best-effort local desktop notification with sanitized metadata only."""
    if not enabled_from_settings(settings):
        return
    min_severity = settings.get("desktop_notifications_min_severity", "high")
    if not severity_allowed(severity, min_severity):
        return
    window_seconds = notification_dedupe_seconds(settings)
    if recently_notified(rule_id, host, action, window_seconds):
        write_jsonl(
            "notification_events.jsonl",
            {
                "sent": False,
                "suppressed": "dedupe",
                "rule_id": rule_id,
                "severity": severity,
                "host": host,
                "action": action,
                "event_id": event_id,
                "request_id": request_id,
                "platform": platform.system(),
            },
        )
        return
    title = f"OpenClaw {action.upper()}: {severity}"
    message = f"Rule: {rule_id}\nHost: {host}\nEvent: {event_id}\nRequest: {request_id}"
    sent = send_desktop_notification(title, message)
    write_jsonl(
        "notification_events.jsonl",
        {
            "sent": sent,
            "rule_id": rule_id,
            "severity": severity,
            "host": host,
            "action": action,
            "event_id": event_id,
            "request_id": request_id,
            "platform": platform.system(),
        },
    )


def notification_dedupe_seconds(settings: dict[str, str]) -> float:
    try:
        return max(0.0, float(settings.get("desktop_notifications_dedupe_seconds", "10")))
    except ValueError:
        return 10.0


def recently_notified(rule_id: str, host: str, action: str, window_seconds: float) -> bool:
    if window_seconds <= 0:
        return False
    now = time.time()
    key = notification_key(rule_id, host, action)
    with _RECENT_LOCK:
        for existing_key, timestamp in list(_RECENT_NOTIFICATIONS.items()):
            if now - timestamp > window_seconds:
                _RECENT_NOTIFICATIONS.pop(existing_key, None)
        last = _RECENT_NOTIFICATIONS.get(key)
        if last is not None and now - last <= window_seconds:
            return True
        if recently_notified_on_disk(key, now, window_seconds):
            return True
        _RECENT_NOTIFICATIONS[key] = now
    return False


def notification_key(rule_id: str, host: str, action: str) -> str:
    return f"{rule_id}|{host}|{action}"


def recently_notified_on_disk(key: str, now: float, window_seconds: float) -> bool:
    LOG_DIR.mkdir(exist_ok=True)
    path = LOG_DIR / "notification_dedupe.json"
    state: dict[str, float] = {}
    if path.exists():
        try:
            state = {str(k): float(v) for k, v in json.loads(path.read_text(encoding="utf-8")).items()}
        except Exception:
            state = {}
    state = {k: v for k, v in state.items() if now - v <= window_seconds}
    last = state.get(key)
    if last is not None and now - last <= window_seconds:
        path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
        return True
    state[key] = now
    path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    return False


def send_desktop_notification(title: str, message: str) -> bool:
    system = platform.system().lower()
    try:
        if system == "linux":
            return send_linux_notification(title, message)
        if system == "windows":
            return send_windows_notification(title, message)
        if system == "darwin":
            return send_macos_notification(title, message)
    except Exception:
        return False
    return False


def send_linux_notification(title: str, message: str) -> bool:
    notify_send = shutil.which("notify-send")
    if not notify_send:
        return False
    if not (os.getenv("DISPLAY") or os.getenv("WAYLAND_DISPLAY") or os.getenv("DBUS_SESSION_BUS_ADDRESS")):
        return False
    subprocess.Popen(
        [notify_send, "--app-name=OpenClaw Governance", "--urgency=normal", "--expire-time=8000", title[:120], message[:800]],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return True


def send_windows_notification(title: str, message: str) -> bool:
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        return False
    script = r"""
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$title = $args[0]
$message = $args[1]
$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = [System.Drawing.SystemIcons]::Shield
$notify.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
$notify.BalloonTipTitle = $title
$notify.BalloonTipText = $message
$notify.Visible = $true
$notify.ShowBalloonTip(8000)
Start-Sleep -Seconds 9
$notify.Dispose()
"""
    subprocess.Popen(
        [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script, title[:120], message[:800]],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return True


def send_macos_notification(title: str, message: str) -> bool:
    osascript = shutil.which("osascript")
    if not osascript:
        return False
    subprocess.Popen(
        [osascript, "-e", "display notification item 2 of argv with title item 1 of argv", title[:120], message[:800]],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return True
