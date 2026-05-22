from __future__ import annotations

import json
from dataclasses import dataclass

from werkzeug.security import check_password_hash, generate_password_hash

from .models import AgentProfile, AgentTag, utcnow
from .utils import generate_token, load_json_list


@dataclass
class AgentIdentity:
    agent_id: str | None
    authenticated: bool
    enabled: bool
    unknown: bool
    policy_mode: str
    tags: set[str]
    reason: str = ""


def hash_agent_token(token: str) -> str:
    return generate_password_hash(token, method="scrypt")


def verify_agent_token(token_hash: str | None, token: str | None) -> bool:
    return bool(token_hash and token and check_password_hash(token_hash, token))


def create_agent_record(session, agent_id: str, name: str, description: str = "", policy_mode: str = "balanced") -> tuple[AgentProfile, str]:
    token = generate_token()
    agent = AgentProfile(id=agent_id, name=name, description=description, policy_mode=policy_mode, agent_token_hash=hash_agent_token(token))
    session.add(agent)
    return agent, token


def rotate_agent_token(agent: AgentProfile) -> str:
    token = generate_token()
    agent.agent_token_hash = hash_agent_token(token)
    agent.updated_at = utcnow()
    return token


def identify_agent(session, headers: dict, source_ip: str, token_required: bool = False, block_unknown: bool = False) -> AgentIdentity:
    agent_id = headers.get("x-openclaw-agent-id") or headers.get("X-OpenClaw-Agent-ID")
    token = headers.get("x-openclaw-agent-token") or headers.get("X-OpenClaw-Agent-Token")
    agent = session.get(AgentProfile, agent_id) if agent_id else None
    if not agent:
        candidates = session.query(AgentProfile).all()
        for candidate in candidates:
            if source_ip in load_json_list(candidate.allowed_source_ips):
                agent = candidate
                break
    if not agent:
        return AgentIdentity(None, not token_required and not block_unknown, True, True, "balanced", set(), "unknown_agent")
    tags = {row.tag for row in session.query(AgentTag).filter_by(agent_id=agent.id).all()}
    authenticated = verify_agent_token(agent.agent_token_hash, token) if token_required or token else True
    agent.last_seen_at = utcnow()
    return AgentIdentity(agent.id, authenticated, bool(agent.enabled), False, agent.policy_mode or "balanced", tags, "" if authenticated else "bad_token")
