#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
exec .venv/bin/gunicorn \
  --bind 127.0.0.1:8899 \
  --workers 2 \
  --threads 4 \
  --access-logfile - \
  --error-logfile - \
  --capture-output \
  --log-level info \
  'openclaw_governance_proxy.app:app'
