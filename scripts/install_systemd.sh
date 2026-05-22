#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_USER="${SUDO_USER:-$(id -un)}"
RUN_GROUP="$(id -gn "$RUN_USER")"
PYTHON_BIN="$PROJECT_ROOT/.venv/bin/python"
GUNICORN_BIN="$PROJECT_ROOT/.venv/bin/gunicorn"
MITMDUMP_BIN="$PROJECT_ROOT/.venv/bin/mitmdump"
ENV_FILE="$PROJECT_ROOT/.env"

if [ ! -x "$GUNICORN_BIN" ] || [ ! -x "$MITMDUMP_BIN" ]; then
  echo "Missing virtualenv tools. Run: bash scripts/install.sh" >&2
  exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
  echo "Missing .env. Run: bash scripts/install.sh" >&2
  exit 1
fi

sudo tee /etc/systemd/system/openclaw-governance-ui.service >/dev/null <<EOF
[Unit]
Description=OpenClaw Governance UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_GROUP
WorkingDirectory=$PROJECT_ROOT
EnvironmentFile=$ENV_FILE
ExecStart=$GUNICORN_BIN --bind 127.0.0.1:8899 --workers 2 --threads 4 --access-logfile - --error-logfile - --capture-output --log-level info openclaw_governance_proxy.app:app
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=false
ReadWritePaths=$PROJECT_ROOT/logs $PROJECT_ROOT/data $PROJECT_ROOT/config $PROJECT_ROOT/instance

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/openclaw-governance-proxy.service >/dev/null <<EOF
[Unit]
Description=OpenClaw Governance HTTPS Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_GROUP
WorkingDirectory=$PROJECT_ROOT
EnvironmentFile=$ENV_FILE
ExecStart=$MITMDUMP_BIN --listen-host 127.0.0.1 --listen-port 8888 -s $PROJECT_ROOT/openclaw_governance_proxy/addon.py
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=false
ReadWritePaths=$PROJECT_ROOT/logs $PROJECT_ROOT/data $PROJECT_ROOT/config $PROJECT_ROOT/instance

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload

cat <<EOF
Systemd services installed:
  openclaw-governance-ui.service
  openclaw-governance-proxy.service

Start now:
  sudo systemctl start openclaw-governance-ui
  sudo systemctl start openclaw-governance-proxy

Enable on boot:
  sudo systemctl enable openclaw-governance-ui
  sudo systemctl enable openclaw-governance-proxy

View logs:
  journalctl -u openclaw-governance-ui -f
  journalctl -u openclaw-governance-proxy -f

Open UI:
  http://127.0.0.1:8899
EOF
