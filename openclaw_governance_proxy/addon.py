from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from html import escape
from pathlib import Path

from mitmproxy import ctx, http

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from openclaw_governance_proxy.agent_identity import identify_agent
from openclaw_governance_proxy.cache import TTLCache
from openclaw_governance_proxy.database import session_scope
from openclaw_governance_proxy.logging_jsonl import write_jsonl
from openclaw_governance_proxy.models import ProxyEventIndex, Setting
from openclaw_governance_proxy.policy import evaluate_policy, is_text_like, strongest_match
from openclaw_governance_proxy.redaction import redact_headers, redact_text
from openclaw_governance_proxy.rules import load_active_rules
from openclaw_governance_proxy.system_notifications import notify_governance_event
from openclaw_governance_proxy.utils import body_hash16, redact_url, safe_header_value

SAFE_HEADERS = {"content-type", "accept", "user-agent", "host", "x-openclaw-agent-id"}
cache = TTLCache(ttl_seconds=5)
DEBUG_WS_SNIPPETS = os.getenv("OPENCLAW_DEBUG_WS_SNIPPETS", "false").lower() == "true"
CODEX_SKIP_KEYS = {
    "instructions",
    "tools",
    "parameters",
    "properties",
    "description",
    "reasoning",
    "metadata",
    "schema",
}
CODEX_INCLUDE_KEYS = {
    "input",
    "messages",
    "message",
    "content",
    "text",
    "prompt",
    "query",
    "body",
    "user",
}
MAX_PLAIN_CODEX_INPUT_LENGTH = 8000
MAX_CODEX_PARSE_BYTES = 2 * 1024 * 1024


def get_settings(session) -> dict[str, str]:
    return {row.key: row.value for row in session.query(Setting).all()}


def safe_headers(headers) -> dict:
    return redact_headers({k: v for k, v in headers.items() if k.lower() in SAFE_HEADERS})


def bounded_text(text: str, max_size: int) -> str:
    if max_size <= 0:
        return ""
    if len(text) <= max_size:
        return text
    head_size = max(1, max_size // 2)
    tail_size = max(1, max_size - head_size)
    return text[:head_size] + "\n[OPENCLAW_GOVERNANCE_TRUNCATED_MIDDLE]\n" + text[-tail_size:]


def bounded_decode(raw: bytes, max_size: int) -> str:
    if len(raw) <= max_size:
        return raw.decode("utf-8", "replace")
    head_size = max(1, max_size // 2)
    tail_size = max(1, max_size - head_size)
    sampled = raw[:head_size] + b"\n[OPENCLAW_GOVERNANCE_TRUNCATED_MIDDLE]\n" + raw[-tail_size:]
    return sampled.decode("utf-8", "replace")


def text_body(message, max_size: int) -> str:
    ctype = message.headers.get("content-type", "")
    if not is_text_like(ctype):
        return ""
    raw = message.raw_content or b""
    return bounded_decode(raw, max_size)


def codex_json_body(message) -> str:
    raw = message.raw_content or b""
    if len(raw) > MAX_CODEX_PARSE_BYTES:
        return ""
    return raw.decode("utf-8", "replace")


def is_codex_request(flow: http.HTTPFlow) -> bool:
    return flow.request.host == "chatgpt.com" and "/backend-api/codex/responses" in flow.request.path


def extract_codex_policy_text(frame_text: str, max_size: int) -> str:
    try:
        data = json.loads(frame_text)
    except Exception:
        return bounded_text(frame_text, max_size)

    if not isinstance(data, dict):
        return ""

    current_input = first_present(data, ("input", "messages", "message"))
    if current_input is None:
        return ""

    latest_user_text = extract_latest_user_text(current_input)
    if latest_user_text:
        return bounded_text(latest_user_text, max_size)

    latest_input_text = extract_latest_input_text(current_input)
    if latest_input_text:
        return bounded_text(latest_input_text, max_size)

    return ""


def first_present(data: dict, keys: tuple[str, ...]):
    for key in keys:
        if key in data:
            return data[key]
    return None


def extract_latest_input_text(value) -> str:
    """Best-effort fallback for provider frames without explicit user roles."""
    if isinstance(value, str):
        if not has_transcript_user_marker(value) and len(value) > MAX_PLAIN_CODEX_INPUT_LENGTH:
            return ""
        return latest_transcript_turn(value)
    if isinstance(value, list):
        collected: list[str] = []
        for item in value:
            text = "\n".join(part for part in extract_text_parts(item) if part.strip())
            if is_meaningful_user_text(text):
                collected.append(text)
        return collected[-1] if collected else ""
    text = "\n".join(part for part in extract_text_parts(value) if part.strip())
    return text if is_meaningful_user_text(text) else ""


def latest_transcript_turn(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    markers = ("\nUser:", "\nuser:", "\nHuman:", "\nhuman:", "User:", "user:", "Human:", "human:")
    latest_index = -1
    latest_marker = ""
    for marker in markers:
        index = text.rfind(marker)
        if index > latest_index:
            latest_index = index
            latest_marker = marker
    if latest_index < 0:
        return text
    turn = text[latest_index + len(latest_marker) :].strip()
    for stop in ("\nAssistant:", "\nassistant:", "\nSystem:", "\nsystem:"):
        stop_index = turn.find(stop)
        if stop_index >= 0:
            turn = turn[:stop_index].strip()
    return turn


def has_transcript_user_marker(value: str) -> bool:
    return any(marker in value for marker in ("\nUser:", "\nuser:", "\nHuman:", "\nhuman:", "User:", "user:", "Human:", "human:"))


def extract_text_parts(value, key: str = "", depth: int = 0) -> list[str]:
    if depth > 10:
        return []
    normalized_key = key.lower()
    if normalized_key in CODEX_SKIP_KEYS:
        return []
    if isinstance(value, str):
        if normalized_key in CODEX_INCLUDE_KEYS or normalized_key in {"", "input_text"}:
            return [value]
        return []
    if isinstance(value, list):
        found: list[str] = []
        for item in value[:200]:
            found.extend(extract_text_parts(item, key, depth + 1))
        return found
    if isinstance(value, dict):
        found = []
        for child_key, child_value in value.items():
            found.extend(extract_text_parts(child_value, str(child_key), depth + 1))
        return found
    return []


def is_meaningful_user_text(value: str) -> bool:
    text = value.strip()
    if not text:
        return False
    lowered = text.lower()
    if lowered.startswith("sender (untrusted metadata):"):
        return False
    if '"label": "openclaw-' in lowered and '"id": "openclaw-' in lowered:
        return False
    return True


def extract_latest_user_text(data) -> str:
    """Extract the newest user-authored text from Codex/OpenClaw request JSON.

    OpenClaw sends large provider frames that include stable instructions, tool
    schemas, and often prior session context. For WebSocket governance, the
    least surprising behavior is to evaluate the current user turn when the
    provider schema exposes roles, then fall back to broad extraction.
    """
    user_messages: list[str] = []

    def walk(value, key: str = "", depth: int = 0) -> None:
        if depth > 12:
            return
        normalized_key = key.lower()
        if normalized_key in CODEX_SKIP_KEYS:
            return
        if isinstance(value, dict):
            role = str(value.get("role") or value.get("author", {}).get("role") or "").lower()
            if role == "user":
                content = value.get("content", value.get("text", value.get("message", value)))
                text = "\n".join(part for part in extract_text_parts(content) if part.strip())
                if is_meaningful_user_text(text):
                    user_messages.append(text)
                return
            for child_key, child_value in value.items():
                walk(child_value, str(child_key), depth + 1)
            return
        if isinstance(value, list):
            for item in value[:200]:
                walk(item, key, depth + 1)

    walk(data)
    return user_messages[-1] if user_messages else ""


def looks_like_user_text(value: str) -> bool:
    if len(value) < 3:
        return False
    lowered = value.lower()
    return any(marker in lowered for marker in ("ignore", "previous", "http://", "https://", "system prompt", "jailbreak", "token", "secret"))


def wants_html_block_page(flow: http.HTTPFlow) -> bool:
    accept = flow.request.headers.get("accept", "").lower()
    return "text/html" in accept or "application/xhtml+xml" in accept


def block_page_html(rule_id: str, severity: str, agent_id: str | None, request_id: str, matched: str = "", event_id: int | None = None) -> str:
    matched_preview = escape(matched[:180]) if matched else "Not available"
    event_label = escape(str(event_id)) if event_id is not None else "pending"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Blocked by OpenClaw Governance</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #050816;
      --panel: #0f172a;
      --line: #334155;
      --text: #e5e7eb;
      --muted: #94a3b8;
      --danger: #ef4444;
      --accent: #38bdf8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: radial-gradient(circle at top left, #172554 0, transparent 32rem), var(--bg);
      color: var(--text);
      font: 16px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{
      width: min(820px, calc(100vw - 32px));
      border: 1px solid var(--line);
      border-radius: 16px;
      background: rgba(15, 23, 42, .94);
      box-shadow: 0 24px 80px rgba(0, 0, 0, .45);
      overflow: hidden;
    }}
    header {{
      padding: 24px 28px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(135deg, rgba(239,68,68,.18), rgba(56,189,248,.08));
    }}
    .eyebrow {{
      color: var(--danger);
      font-size: 13px;
      font-weight: 800;
      letter-spacing: .08em;
      text-transform: uppercase;
    }}
    h1 {{
      margin: 8px 0 0;
      font-size: clamp(28px, 4vw, 44px);
      line-height: 1.1;
    }}
    section {{ padding: 24px 28px 28px; }}
    .message {{
      margin: 0 0 20px;
      color: var(--muted);
      max-width: 68ch;
    }}
    dl {{
      display: grid;
      grid-template-columns: 160px 1fr;
      gap: 10px 18px;
      margin: 0;
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: rgba(2, 6, 23, .45);
    }}
    dt {{ color: var(--muted); }}
    dd {{
      margin: 0;
      min-width: 0;
      overflow-wrap: anywhere;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }}
    .badge {{
      display: inline-block;
      padding: 2px 9px;
      border-radius: 999px;
      background: rgba(239, 68, 68, .14);
      color: #fecaca;
      border: 1px solid rgba(239, 68, 68, .38);
      font-family: inherit;
      font-weight: 700;
    }}
    .hint {{
      margin-top: 18px;
      color: var(--muted);
      font-size: 14px;
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div class="eyebrow">OpenClaw Governance Proxy</div>
      <h1>Request blocked</h1>
    </header>
    <section>
      <p class="message">This browser request matched a governance policy and was stopped before it reached the destination.</p>
      <dl>
        <dt>Rule</dt><dd>{escape(rule_id)}</dd>
        <dt>Severity</dt><dd><span class="badge">{escape(severity)}</span></dd>
        <dt>Matched</dt><dd>{matched_preview}</dd>
        <dt>Agent</dt><dd>{escape(agent_id or "unknown")}</dd>
        <dt>Request ID</dt><dd>{escape(request_id)}</dd>
        <dt>Event ID</dt><dd>{event_label}</dd>
      </dl>
      <p class="hint">Use the Events page in the local UI for sanitized details. Full request bodies and secrets are not shown.</p>
    </section>
  </main>
</body>
</html>"""


class GovernanceAddon:
    def __init__(self):
        self.fail_closed = False

    def load_rules(self, session):
        cached = cache.get()
        if cached is not None:
            return cached
        rules = load_active_rules(session)
        cache.set(rules)
        return rules

    def request(self, flow: http.HTTPFlow) -> None:
        request_id = flow.request.headers.get("X-OpenClaw-Request-ID") or str(uuid.uuid4())
        flow.metadata["openclaw_request_id"] = request_id
        source_ip = flow.client_conn.peername[0] if flow.client_conn and flow.client_conn.peername else ""
        with session_scope() as session:
            settings = get_settings(session)
            identity = identify_agent(
                session,
                dict(flow.request.headers),
                source_ip,
                token_required=settings.get("agent_token_required") == "true",
                block_unknown=settings.get("block_unknown_agents") == "true",
            )
            flow.metadata["openclaw_agent_id"] = identity.agent_id
            if not identity.authenticated or not identity.enabled or (identity.unknown and settings.get("block_unknown_agents") == "true"):
                self.block(flow, "agent-authentication", "critical", identity.agent_id, request_id)
                return
            if settings.get("inspect_requests", "true") != "true":
                return
            try:
                rules = self.load_rules(session)
                self.fail_closed = False
            except Exception as exc:
                logging.exception("critical policy load failed")
                self.fail_closed = True
                self.block(flow, "policy-load-failure", "critical", identity.agent_id, request_id)
                return
            max_size = int(settings.get("max_inspect_body_size", "65536"))
            if is_codex_request(flow):
                original_body = codex_json_body(flow.request)
                body = extract_codex_policy_text(original_body, max_size) if original_body else ""
                if DEBUG_WS_SNIPPETS:
                    self.log_codex_debug(flow, identity.agent_id, request_id, original_body, body, "http_request")
            else:
                original_body = text_body(flow.request, max_size)
                body = original_body
            matches = evaluate_policy(
                rules,
                direction="request",
                host=flow.request.host,
                url=flow.request.pretty_url,
                method=flow.request.method,
                headers=safe_headers(flow.request.headers),
                body=body,
                content_type=flow.request.headers.get("content-type", ""),
                agent_id=identity.agent_id,
                agent_tags=identity.tags,
                policy_mode=identity.policy_mode or settings.get("policy_mode", "balanced"),
            )
            self.apply(flow, matches, "request", identity.agent_id, request_id, body)

    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.response:
            return
        request_id = flow.metadata.get("openclaw_request_id") or str(uuid.uuid4())
        agent_id = flow.metadata.get("openclaw_agent_id")
        with session_scope() as session:
            settings = get_settings(session)
            if settings.get("inspect_responses", "true") != "true":
                return
            try:
                rules = self.load_rules(session)
            except Exception:
                flow.response = self.block_response(flow, "policy-load-failure", "critical", agent_id, request_id)
                return
            max_size = int(settings.get("max_inspect_body_size", "65536"))
            body = text_body(flow.response, max_size)
            matches = evaluate_policy(
                rules,
                direction="response",
                host=flow.request.host,
                url=flow.request.pretty_url,
                method=flow.request.method,
                headers=safe_headers(flow.response.headers),
                body=body,
                content_type=flow.response.headers.get("content-type", ""),
                agent_id=agent_id,
                policy_mode=settings.get("policy_mode", "balanced"),
            )
            self.apply(flow, matches, "response", agent_id, request_id, body)

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        if not flow.websocket or not flow.websocket.messages:
            return
        message = flow.websocket.messages[-1]
        if not getattr(message, "is_text", False):
            return
        request_id = flow.metadata.get("openclaw_request_id") or str(uuid.uuid4())
        flow.metadata["openclaw_request_id"] = request_id
        source_ip = flow.client_conn.peername[0] if flow.client_conn and flow.client_conn.peername else ""
        direction = "request" if message.from_client else "response"
        with session_scope() as session:
            settings = get_settings(session)
            if direction == "request" and settings.get("inspect_requests", "true") != "true":
                return
            if direction == "response" and settings.get("inspect_responses", "true") != "true":
                return
            identity = identify_agent(
                session,
                dict(flow.request.headers),
                source_ip,
                token_required=settings.get("agent_token_required") == "true",
                block_unknown=settings.get("block_unknown_agents") == "true",
            )
            flow.metadata["openclaw_agent_id"] = identity.agent_id
            try:
                rules = self.load_rules(session)
            except Exception:
                flow.kill()
                return
            if flow.request.host == "chatgpt.com":
                rules = [rule for rule in rules if rule.match_type != "secret_detector"]
            max_size = int(settings.get("max_inspect_body_size", "65536"))
            original_text = message.text
            text = extract_codex_policy_text(original_text, max_size) if direction == "request" and is_codex_request(flow) else bounded_text(original_text, max_size)
            matches = evaluate_policy(
                rules,
                direction=direction,
                host=flow.request.host,
                url=flow.request.pretty_url,
                method="WEBSOCKET",
                headers=safe_headers(flow.request.headers),
                body=text,
                content_type="text/plain",
                agent_id=identity.agent_id,
                agent_tags=identity.tags,
                policy_mode=identity.policy_mode or settings.get("policy_mode", "balanced"),
            )
            if DEBUG_WS_SNIPPETS and direction == "request":
                self.log_codex_debug(flow, identity.agent_id, request_id, original_text, text, f"websocket_{direction}")
            self.apply_websocket(flow, message, matches, direction, identity.agent_id, request_id, text)

    def apply(self, flow: http.HTTPFlow, matches, direction: str, agent_id: str | None, request_id: str, body: str) -> None:
        match = strongest_match(matches)
        if not match:
            return
        event_id = self.log_event(flow, match, direction, agent_id, request_id, body)
        if match.action == "block":
            if direction == "request":
                self.block(flow, match.rule.id, match.rule.severity, agent_id, request_id, match.matched, event_id)
            else:
                flow.response = self.block_response(flow, match.rule.id, match.rule.severity, agent_id, request_id, match.matched, event_id)
        elif match.action == "redact":
            msg = flow.request if direction == "request" else flow.response
            if msg and is_text_like(msg.headers.get("content-type", "")):
                msg.text = redact_text(msg.text)
        elif match.action == "warn":
            target = flow.response if direction == "response" and flow.response else flow.request
            target.headers["x-openclaw-governance-warning"] = safe_header_value(f"rule={match.rule.id}; severity={match.rule.severity}")

    def apply_websocket(self, flow: http.HTTPFlow, message, matches, direction: str, agent_id: str | None, request_id: str, body: str) -> None:
        match = strongest_match(matches)
        if not match:
            return
        self.log_event(flow, match, f"websocket_{direction}", agent_id, request_id, body)
        # Codex/OpenClaw WebSocket frames use provider-specific JSON protocols.
        # Rewriting or injecting frames can corrupt those protocols. For block
        # actions, close the flow without mutating frame content.
        if match.action == "block":
            message.drop()
            flow.kill()
        return

    def log_codex_debug(self, flow: http.HTTPFlow, agent_id: str | None, request_id: str, original_body: str, extracted_body: str, direction: str) -> None:
        redacted_original = redact_text(original_body)
        redacted_extracted = redact_text(extracted_body)
        write_jsonl(
            "codex_debug.jsonl",
            {
                "request_id": request_id,
                "agent_id": agent_id,
                "host": flow.request.host,
                "direction": direction,
                "redacted_url": redact_url(flow.request.pretty_url),
                "original_sha256_16": body_hash16(original_body),
                "extracted_sha256_16": body_hash16(extracted_body),
                "message_count": len(flow.websocket.messages) if flow.websocket else None,
                "original_length": len(original_body),
                "extracted_length": len(extracted_body),
                "original_head": redacted_original[:1000],
                "original_tail": redacted_original[-1000:],
                "extracted_head": redacted_extracted[:1000],
                "extracted_tail": redacted_extracted[-1000:],
            },
        )

    def block(self, flow: http.HTTPFlow, rule_id: str, severity: str, agent_id: str | None, request_id: str, matched: str = "", event_id: int | None = None) -> None:
        flow.response = self.block_response(flow, rule_id, severity, agent_id, request_id, matched, event_id)

    def block_response(self, flow: http.HTTPFlow | None, rule_id: str, severity: str, agent_id: str | None, request_id: str, matched: str = "", event_id: int | None = None):
        if flow is not None and wants_html_block_page(flow):
            return http.Response.make(
                403,
                block_page_html(rule_id, severity, agent_id, request_id, matched, event_id),
                {
                    "Content-Type": "text/html; charset=utf-8",
                    "Cache-Control": "no-store",
                    "x-openclaw-governance-blocked": "true",
                    "x-openclaw-governance-rule": safe_header_value(rule_id),
                    "x-openclaw-governance-severity": safe_header_value(severity),
                    "x-openclaw-governance-request-id": safe_header_value(request_id),
                },
            )
        return http.Response.make(
            403,
            json.dumps(
                {
                    "status": "blocked",
                    "reason": "Forbidden governance rule matched",
                    "message": "FORBIDDEN ACTION: This request or response matched an OpenClaw governance policy and was blocked.",
                    "rule_id": rule_id,
                    "severity": severity,
                    "agent_id": agent_id,
                    "request_id": request_id,
                    "event_id": event_id,
                }
            ),
            {
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                "x-openclaw-governance-blocked": "true",
                "x-openclaw-governance-rule": safe_header_value(rule_id),
                "x-openclaw-governance-severity": safe_header_value(severity),
                "x-openclaw-governance-request-id": safe_header_value(request_id),
            },
        )

    def log_event(self, flow, match, direction: str, agent_id: str | None, request_id: str, body: str) -> int:
        source_ip = flow.client_conn.peername[0] if flow.client_conn and flow.client_conn.peername else ""
        status = flow.response.status_code if flow.response else None
        event_direction = direction if direction in {"request", "response"} else direction
        event = {
            "request_id": request_id,
            "agent_id": agent_id,
            "source_ip": source_ip,
            "severity": match.rule.severity,
            "action": match.action,
            "rule_id": match.rule.id,
            "direction": event_direction,
            "host": flow.request.host,
            "method": flow.request.method,
            "status_code": status,
            "content_type": (flow.response or flow.request).headers.get("content-type", ""),
            "redacted_url": redact_url(flow.request.pretty_url),
            "body_sha256_16": body_hash16(body),
            "matched": match.matched[:160],
        }
        with session_scope() as session:
            settings = get_settings(session)
            row = ProxyEventIndex(
                **{
                    k: event.get(k)
                    for k in [
                        "request_id",
                        "agent_id",
                        "source_ip",
                        "severity",
                        "action",
                        "rule_id",
                        "direction",
                        "host",
                        "method",
                        "status_code",
                        "content_type",
                        "redacted_url",
                        "body_sha256_16",
                    ]
                },
                details_json=json.dumps({"matched": match.matched[:160]}),
            )
            session.add(row)
            session.flush()
            event["event_id"] = row.id
        write_jsonl("proxy_events.jsonl", event)
        notify_governance_event(
            settings,
            rule_id=match.rule.id,
            severity=match.rule.severity,
            host=flow.request.host,
            action=match.action,
            event_id=int(event["event_id"]),
            request_id=request_id,
        )
        return int(event["event_id"])

    def reload_rules(self):
        cache.invalidate()
        ctx.log.info("OpenClaw governance rule cache invalidated")


addons = [GovernanceAddon()]
