#!/usr/bin/env bash
set -euo pipefail

sudo systemctl disable --now openclaw-governance-ui.service 2>/dev/null || true
sudo systemctl disable --now openclaw-governance-proxy.service 2>/dev/null || true
sudo rm -f /etc/systemd/system/openclaw-governance-ui.service
sudo rm -f /etc/systemd/system/openclaw-governance-proxy.service
sudo systemctl daemon-reload

echo "OpenClaw Governance systemd services removed."
