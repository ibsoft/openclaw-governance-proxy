from __future__ import annotations

from datetime import datetime, timezone

from flask_login import UserMixin
from sqlalchemy import Index, UniqueConstraint

from .database import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="viewer", index=True)
    enabled = db.Column(db.Boolean, default=True, nullable=False, index=True)
    mfa_secret = db.Column(db.String(128))
    failed_login_count = db.Column(db.Integer, default=0)
    last_login_at = db.Column(db.DateTime(timezone=True))
    session_version = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    def is_active(self) -> bool:
        return bool(self.enabled)


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), index=True)
    source_ip = db.Column(db.String(64), index=True)
    success = db.Column(db.Boolean, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)


class Setting(db.Model):
    __tablename__ = "settings"
    key = db.Column(db.String(128), primary_key=True)
    value = db.Column(db.Text, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Rule(db.Model):
    __tablename__ = "rules"
    id = db.Column(db.String(128), primary_key=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    description = db.Column(db.Text, default="")
    enabled = db.Column(db.Boolean, default=True, nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, index=True)
    action = db.Column(db.String(20), nullable=False, index=True)
    direction = db.Column(db.String(20), nullable=False, index=True)
    match_type = db.Column(db.String(32), nullable=False, index=True)
    scope = db.Column(db.String(32), nullable=False, default="global", index=True)
    agent_id = db.Column(db.String(128), db.ForeignKey("agent_profiles.id"), index=True)
    policy_mode = db.Column(db.String(32), index=True)
    patterns = db.Column(db.Text, default="[]")
    domains = db.Column(db.Text, default="[]")
    content_types = db.Column(db.Text, default="[]")
    tags = db.Column(db.Text, default="[]")
    notes = db.Column(db.Text, default="")
    compile_error = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow, index=True)
    created_by = db.Column(db.String(80))
    updated_by = db.Column(db.String(80), index=True)
    deleted_at = db.Column(db.DateTime(timezone=True), index=True)


class RuleChangeHistory(db.Model):
    __tablename__ = "rule_change_history"
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.String(128), index=True)
    actor_user_id = db.Column(db.Integer)
    actor_username = db.Column(db.String(80), index=True)
    action = db.Column(db.String(32), index=True)
    old_value_json = db.Column(db.Text)
    new_value_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)
    source_ip = db.Column(db.String(64), index=True)
    user_agent = db.Column(db.String(512))


class AgentProfile(db.Model):
    __tablename__ = "agent_profiles"
    id = db.Column(db.String(128), primary_key=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    description = db.Column(db.Text, default="")
    enabled = db.Column(db.Boolean, default=True, nullable=False, index=True)
    agent_token_hash = db.Column(db.String(255))
    allowed_source_ips = db.Column(db.Text, default="[]")
    policy_mode = db.Column(db.String(32), default="balanced", index=True)
    assigned_rule_set = db.Column(db.String(128), default="")
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow, index=True)
    last_seen_at = db.Column(db.DateTime(timezone=True), index=True)


class AgentTag(db.Model):
    __tablename__ = "agent_tags"
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(128), db.ForeignKey("agent_profiles.id"), index=True)
    tag = db.Column(db.String(64), index=True)
    __table_args__ = (UniqueConstraint("agent_id", "tag"),)


class AgentPolicyAssignment(db.Model):
    __tablename__ = "agent_policy_assignments"
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(128), db.ForeignKey("agent_profiles.id"), index=True)
    rule_id = db.Column(db.String(128), db.ForeignKey("rules.id"), index=True)


class AgentEvent(db.Model):
    __tablename__ = "agent_events"
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(128), index=True)
    event_type = db.Column(db.String(64), index=True)
    details_json = db.Column(db.Text, default="{}")
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)


class ProxyEventIndex(db.Model):
    __tablename__ = "proxy_events_index"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)
    request_id = db.Column(db.String(64), index=True)
    agent_id = db.Column(db.String(128), index=True)
    source_ip = db.Column(db.String(64), index=True)
    severity = db.Column(db.String(20), index=True)
    action = db.Column(db.String(20), index=True)
    rule_id = db.Column(db.String(128), index=True)
    direction = db.Column(db.String(20), index=True)
    host = db.Column(db.String(255), index=True)
    method = db.Column(db.String(16))
    status_code = db.Column(db.Integer, index=True)
    content_type = db.Column(db.String(128))
    redacted_url = db.Column(db.Text)
    body_sha256_16 = db.Column(db.String(16))
    details_json = db.Column(db.Text, default="{}")


class UIAuditEvent(db.Model):
    __tablename__ = "ui_audit_events"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)
    actor = db.Column(db.String(80), index=True)
    role = db.Column(db.String(20), index=True)
    source_ip = db.Column(db.String(64), index=True)
    event = db.Column(db.String(64), index=True)
    object_type = db.Column(db.String(64), index=True)
    object_id = db.Column(db.String(128), index=True)
    agent_id = db.Column(db.String(128), index=True)
    result = db.Column(db.String(32), index=True)
    severity = db.Column(db.String(20), index=True)
    details_json = db.Column(db.Text, default="{}")
    request_id = db.Column(db.String(64), index=True)


class Alert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.Integer, primary_key=True)
    severity = db.Column(db.String(20), index=True)
    title = db.Column(db.String(255))
    message = db.Column(db.Text)
    acknowledged = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)


class SystemStatus(db.Model):
    __tablename__ = "system_status"
    key = db.Column(db.String(128), primary_key=True)
    value = db.Column(db.Text)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class CAStatus(db.Model):
    __tablename__ = "ca_status"
    id = db.Column(db.Integer, primary_key=True)
    installed = db.Column(db.Boolean, default=False)
    metadata_json = db.Column(db.Text, default="{}")
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ServiceStatusSnapshot(db.Model):
    __tablename__ = "service_status_snapshots"
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(128), index=True)
    status = db.Column(db.String(64), index=True)
    details_json = db.Column(db.Text, default="{}")
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, index=True)


Index("ix_proxy_events_filters", ProxyEventIndex.timestamp, ProxyEventIndex.agent_id, ProxyEventIndex.rule_id)
Index("ix_audit_filters", UIAuditEvent.timestamp, UIAuditEvent.actor, UIAuditEvent.event)
