#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p logs data instance
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
if [ ! -f .env ]; then
  SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
  TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
  cp .env.example .env
  sed -i "s/replace-with-generated-secret/$SECRET/" .env
  sed -i "s/replace-with-generated-token/$TOKEN/" .env
fi
chmod 700 data logs instance
chmod 600 .env
python -m scripts.create_admin --init-db-only
python - <<'PY'
from openclaw_governance_proxy.app import app
from openclaw_governance_proxy.rules import seed_rules_from_yaml
with app.app_context():
    print("Seeded", seed_rules_from_yaml("config/seed_rules.yaml"), "rules")
PY
echo "Install complete. Create an admin with: .venv/bin/python scripts/create_admin.py"
