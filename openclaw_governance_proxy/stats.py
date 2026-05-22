from __future__ import annotations

from sqlalchemy import func

from .models import AgentProfile, ProxyEventIndex, Rule


def dashboard_stats() -> dict:
    return {
        "total_requests": ProxyEventIndex.query.count(),
        "blocked_events": ProxyEventIndex.query.filter_by(action="block").count(),
        "redacted_events": ProxyEventIndex.query.filter_by(action="redact").count(),
        "warnings": ProxyEventIndex.query.filter_by(action="warn").count(),
        "rules_enabled": Rule.query.filter_by(enabled=True, deleted_at=None).count(),
        "rules_disabled": Rule.query.filter_by(enabled=False, deleted_at=None).count(),
        "active_agents": AgentProfile.query.filter_by(enabled=True).count(),
        "disabled_agents": AgentProfile.query.filter_by(enabled=False).count(),
        "unknown_agent_events": ProxyEventIndex.query.filter_by(agent_id=None).count(),
    }


def grouped_counts(column, limit: int = 10):
    return ProxyEventIndex.query.with_entities(column, func.count(ProxyEventIndex.id)).group_by(column).order_by(func.count(ProxyEventIndex.id).desc()).limit(limit).all()
