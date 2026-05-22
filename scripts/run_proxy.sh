#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
exec .venv/bin/mitmdump --listen-host 127.0.0.1 --listen-port 8888 -s openclaw_governance_proxy/addon.py
