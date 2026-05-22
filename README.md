# openclaw-governance-proxy

Local-first HTTPS governance proxy for OpenClaw and other AI agents.

## What This Is

`openclaw-governance-proxy` routes agent traffic through `mitmdump`, evaluates outbound requests and inbound responses against governance rules, and records sanitized audit metadata in SQLite and JSONL logs. Flask provides the local secure control plane and web UI for authentication, rules, agents, settings, events, audit logs, statistics, CA guidance, and OpenClaw routing instructions.

Traffic path:

```text
OpenClaw Agent -> HTTP_PROXY/HTTPS_PROXY -> mitmdump governance addon -> Internet
```

## What This Is Not

This is not a complete security boundary, not an internet-facing proxy, and not a replacement for endpoint controls, secrets management, network egress controls, or vendor-specific AI safety systems. SQLite is appropriate for local-first deployments; high-volume enterprise deployments may later need PostgreSQL.

## Architecture

- `mitmproxy/mitmdump` is the HTTPS interception data plane.
- Flask is the local control plane and Web UI.
- SQLite is the source of truth for live configuration: rules, settings, users, roles, agents, policies, audit events, proxy event indexes, alerts, CA status, and service status snapshots.
- YAML is used only for initial seed rules, import/export, backup, and examples.
- SQLAlchemy is configured for SQLite WAL mode, `synchronous=NORMAL`, foreign keys, and `busy_timeout`.

## Security Model

The proxy inspects text-like HTTP content only: `text/*`, JSON, XML, XHTML, JavaScript, and URL-encoded form bodies. It never logs full request or response bodies by default. Authorization headers, cookies, API keys, bearer tokens, passwords, secrets, private keys, database URLs, OAuth tokens, session cookies, and similar values are redacted.

Rule actions:

- `monitor`: allow and log metadata.
- `warn`: allow and add `X-OpenClaw-Governance-Warning` where possible.
- `redact`: replace matched sensitive text with `[REDACTED_BY_GOVERNANCE]`.
- `block`: return HTTP 403 JSON with rule, severity, agent, and request correlation IDs.

The UI uses CSRF protection, role-based authorization, secure cookie settings, restrictive security headers, rate limiting, password hashing, generic login failures, server-side pagination, and POST-only state changes.

## Important Warnings

- Do not expose the proxy to the Internet.
- Do not expose the UI to the Internet without a reverse proxy, TLS, MFA, and IP allowlisting.
- Do not install the mitmproxy CA on systems you do not own or govern.
- Do not disable upstream TLS verification.
- Do not log secrets.
- Some applications ignore `HTTP_PROXY` and `HTTPS_PROXY`; they need app-specific proxy configuration or transparent proxying.

## Install

```bash
bash scripts/install.sh
.venv/bin/python scripts/create_admin.py
```

The installer creates a virtualenv, installs dependencies, creates `logs`, `data`, and `instance`, generates `.env` secrets if missing, initializes SQLite, enables WAL mode, and seeds rules from `config/seed_rules.yaml`.

## Run

UI:

```bash
bash scripts/run_ui.sh
```

Proxy:

```bash
bash scripts/run_proxy.sh
```

Defaults:

- Proxy: `127.0.0.1:8888`
- UI: `127.0.0.1:8899`

Gunicorn is used for the UI. Flask debug mode is not used.

## HTTPS Interception and CA

HTTPS inspection requires installing the mitmproxy CA certificate on governed hosts. Without CA trust, HTTPS clients will fail certificate verification or only CONNECT-level domain inspection will work.

```bash
bash scripts/install_ca.sh
bash scripts/uninstall_ca.sh
```

Never expose the private mitmproxy CA key through the UI.

## Multi-Agent Model

Agents have an ID, name, description, enabled flag, hashed token, source IP mappings, policy mode, assigned rules, tags, timestamps, and last-seen metadata. Token values are shown only once at creation or rotation.

Create an agent:

```bash
.venv/bin/python scripts/create_agent.py agent1 "OpenClaw Agent 1"
```

Agent identity supports:

- `X-OpenClaw-Agent-ID`
- `X-OpenClaw-Agent-Token`
- source IP fallback
- future mTLS metadata hook points

If `agent_token_required=true`, the ID alone is not trusted.

## Route OpenClaw

Shell-launched agent:

```bash
export HTTP_PROXY=http://127.0.0.1:8888
export HTTPS_PROXY=http://127.0.0.1:8888
export NO_PROXY=127.0.0.1,localhost
export OPENCLAW_AGENT_ID="<agent_id>"
export OPENCLAW_AGENT_TOKEN="<agent_token>"
openclaw gateway start
```

For a systemd user service:

```bash
systemctl --user edit openclaw-gateway
systemctl --user daemon-reload
systemctl --user restart openclaw-gateway
systemctl --user show openclaw-gateway --property=Environment
```

Add:

```ini
[Service]
Environment="HTTP_PROXY=http://127.0.0.1:8888"
Environment="HTTPS_PROXY=http://127.0.0.1:8888"
Environment="NO_PROXY=127.0.0.1,localhost"
Environment="OPENCLAW_AGENT_ID=<agent_id>"
Environment="OPENCLAW_AGENT_TOKEN=<agent_token>"
```

For a system service, use `sudo systemctl edit openclaw-gateway` and the same environment block.

If a client can inject headers, configure:

```text
X-OpenClaw-Agent-ID: <agent_id>
X-OpenClaw-Agent-Token: <agent_token>
```

If it cannot, configure source-IP mapping as a fallback.

## Rules

Rules are managed in the UI and stored in SQLite. Default categories include prompt injection, system prompt extraction, developer message extraction, chain-of-thought extraction, policy bypass, jailbreaks, role override, unsafe tool-use instructions, agent instruction override, credential exfiltration, secret leakage, private keys, environment variables, local files, suspicious paste/webhook destinations, SSRF metadata endpoints, malware-like instructions, dangerous autonomy, unauthorized scanning, privacy/PII leakage, API tokens, OAuth tokens, database URLs, SSH keys, Git credentials, and prompt injection in upstream pages.

Lifecycle support:

- create, view, edit, enable, disable, soft delete, clone
- test rules in the policy tester
- import/export YAML
- reload compiled rules
- full rule history and UI audit entries

Policy modes:

- `strict`
- `balanced` default
- `monitor_only`
- `assessment_mode`

## Audit and Logs

Database-backed UI audit logs and proxy event indexes are available in the UI with filters and server-side pagination.

Files:

- `logs/proxy_events.jsonl`
- `logs/ui_audit_events.jsonl`
- `logs/app.log`
- `logs/security.log`
- `logs/rule_changes.jsonl`

Rotate logs:

```bash
bash scripts/rotate_logs.sh
```

Exports are role-protected and audited.

## Systemd

Install system services for the current checkout:

```bash
bash scripts/install_systemd.sh
sudo systemctl start openclaw-governance-ui
sudo systemctl start openclaw-governance-proxy
sudo systemctl enable openclaw-governance-ui
sudo systemctl enable openclaw-governance-proxy
```

View live logs:

```bash
journalctl -u openclaw-governance-ui -f
journalctl -u openclaw-governance-proxy -f
```

Remove services:

```bash
bash scripts/uninstall_systemd.sh
```

Reference unit files are also in `systemd/`.

Proxy hardening includes `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=full`, and scoped `ReadWritePaths`.

UI runs Gunicorn on `127.0.0.1:8899` with worker threads.

## Test Blocking

```bash
bash scripts/test_proxy.sh
```

The script checks normal HTTPS traffic, prompt injection blocking, secret leakage blocking, metadata endpoint blocking, allowed traffic, authenticated agent traffic, unknown-agent behavior, and latest events.

Unit tests:

```bash
pytest
```

## Troubleshooting

- HTTPS failures usually mean the governed host does not trust the mitmproxy CA.
- Empty UI tables usually mean traffic has not yet matched a rule; metadata-only events are recorded on matches.
- If a client ignores `HTTP_PROXY`, configure the proxy inside that client or service.
- If SQLite is busy under load, verify WAL mode and reduce long-running UI exports.
- If rules fail to reload, check the rule compile error in the rules table and `logs/app.log`.
