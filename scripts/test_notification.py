#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from openclaw_governance_proxy.system_notifications import send_desktop_notification


def main() -> None:
    sent = send_desktop_notification(
        "OpenClaw Governance Test",
        "Desktop notifications are working for this login session.",
    )
    print("sent=true" if sent else "sent=false")


if __name__ == "__main__":
    main()
