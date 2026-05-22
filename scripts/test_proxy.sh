#!/usr/bin/env bash
set -euo pipefail
PROXY="${PROXY:-http://127.0.0.1:8888}"
echo "1 normal HTTPS request"; curl -ksS -x "$PROXY" https://example.com/ >/dev/null
echo "2 blocked prompt injection"; curl -ksS -x "$PROXY" 'https://example.com/?q=ignore%20previous%20instructions' || true
echo "3 blocked secret leakage"; curl -ksS -x "$PROXY" -d 'api_key=sk-123456789012345678901234' https://example.com/ || true
echo "4 blocked cloud metadata"; curl -ksS -x "$PROXY" http://169.254.169.254/latest/meta-data/ || true
echo "5 allowed normal request"; curl -ksS -x "$PROXY" https://example.com/ >/dev/null
echo "6 agent-authenticated request"; curl -ksS -x "$PROXY" -H "X-OpenClaw-Agent-ID: ${OPENCLAW_AGENT_ID:-demo}" -H "X-OpenClaw-Agent-Token: ${OPENCLAW_AGENT_TOKEN:-demo}" https://example.com/ >/dev/null || true
echo "7 unknown-agent request"; curl -ksS -x "$PROXY" -H "X-OpenClaw-Agent-ID: unknown" https://example.com/ >/dev/null || true
echo "8 latest events"; tail -n 20 logs/proxy_events.jsonl || true
