#!/usr/bin/env bash
set -euo pipefail

CA_PEM="${MITMPROXY_CA_PEM:-$HOME/.mitmproxy/mitmproxy-ca-cert.pem}"
SYSTEM_CA="/usr/local/share/ca-certificates/openclaw-mitmproxy.crt"

if [ ! -f "$CA_PEM" ]; then
  cat >&2 <<EOF
mitmproxy CA not found:
  $CA_PEM

Start the proxy once so mitmproxy generates it:
  bash scripts/run_proxy.sh

Then rerun:
  bash scripts/install_ca.sh
EOF
  exit 1
fi

echo "Installing mitmproxy CA for this governed host:"
echo "  source: $CA_PEM"
echo "  target: $SYSTEM_CA"
sudo cp "$CA_PEM" "$SYSTEM_CA"
sudo chmod 0644 "$SYSTEM_CA"

if command -v update-ca-certificates >/dev/null 2>&1; then
  sudo update-ca-certificates
else
  echo "update-ca-certificates not found. Install the CA manually for this distribution." >&2
fi

cat <<EOF

System trust store updated.

For OpenClaw/Node.js processes, also set:
  export NODE_EXTRA_CA_CERTS="$CA_PEM"

For OpenClaw managed gateway services, put this in the service environment
or ~/.openclaw/.env, then restart/reinstall the gateway:
  NODE_EXTRA_CA_CERTS=$CA_PEM

Only install this CA on hosts intentionally governed by this proxy.
EOF
