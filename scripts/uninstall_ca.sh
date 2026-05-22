#!/usr/bin/env bash
set -euo pipefail

SYSTEM_CA="/usr/local/share/ca-certificates/openclaw-mitmproxy.crt"

echo "Removing OpenClaw mitmproxy CA from system trust store:"
echo "  $SYSTEM_CA"
sudo rm -f "$SYSTEM_CA"

if command -v update-ca-certificates >/dev/null 2>&1; then
  sudo update-ca-certificates --fresh
else
  echo "update-ca-certificates not found. Remove the CA manually for this distribution." >&2
fi

cat <<EOF

If you set NODE_EXTRA_CA_CERTS for OpenClaw, remove that environment entry
and restart/reinstall the OpenClaw gateway service.
EOF
