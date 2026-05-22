#!/usr/bin/env python
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from openclaw_governance_proxy.app import app
from openclaw_governance_proxy.agent_identity import create_agent_record
from openclaw_governance_proxy.database import db


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("agent_id")
    parser.add_argument("name")
    parser.add_argument("--description", default="")
    parser.add_argument("--policy-mode", default="balanced")
    args = parser.parse_args()
    with app.app_context():
        agent, token = create_agent_record(db.session, args.agent_id, args.name, args.description, args.policy_mode)
        db.session.commit()
        print(f"Agent created: {agent.id}")
        print(f"Token shown once: {token}")


if __name__ == "__main__":
    main()
