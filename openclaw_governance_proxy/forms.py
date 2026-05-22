from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import BooleanField, EmailField, PasswordField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length, Optional

from .validators import VALID_ACTIONS, VALID_DIRECTIONS, VALID_MATCH_TYPES, VALID_SCOPES, VALID_SEVERITIES


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=80)], render_kw={"placeholder": "adm"})
    password = PasswordField("Password", validators=[DataRequired(), Length(max=256)], render_kw={"placeholder": "Enter your admin password"})
    submit = SubmitField("Login")


class UserForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=80)], render_kw={"placeholder": "operator"})
    email = EmailField("Email", validators=[DataRequired(), Length(max=255)], render_kw={"placeholder": "operator@example.com"})
    role = SelectField("Role", choices=[("admin", "admin"), ("viewer", "viewer"), ("auditor", "auditor")])
    enabled = BooleanField("Enabled", default=True)
    password = PasswordField("Password", validators=[Optional(), Length(max=256)], render_kw={"placeholder": "At least 15 characters"})
    password_confirm = PasswordField("Confirm Password", validators=[EqualTo("password")], render_kw={"placeholder": "Repeat password"})
    submit = SubmitField("Save")


class RuleForm(FlaskForm):
    id = StringField("Rule ID", validators=[DataRequired(), Length(max=128)], render_kw={"placeholder": "prompt_injection_ignore_previous"})
    name = StringField("Name", validators=[DataRequired(), Length(max=255)], render_kw={"placeholder": "Prompt injection: ignore previous instructions"})
    description = TextAreaField("Description", render_kw={"placeholder": "Short operational description of what this rule detects", "rows": 3})
    enabled = BooleanField("Enabled", default=True)
    severity = SelectField("Severity", choices=[(x, x) for x in sorted(VALID_SEVERITIES)])
    action = SelectField("Action", choices=[(x, x) for x in sorted(VALID_ACTIONS)])
    direction = SelectField("Direction", choices=[(x, x) for x in sorted(VALID_DIRECTIONS)])
    match_type = SelectField("Match Type", choices=[(x, x) for x in sorted(VALID_MATCH_TYPES)])
    scope = SelectField("Scope", choices=[(x, x) for x in sorted(VALID_SCOPES)])
    agent_id = StringField("Agent ID", validators=[Optional(), Length(max=128)], render_kw={"placeholder": "agent-prod-01"})
    patterns = TextAreaField("Patterns", render_kw={"placeholder": "(?i)ignore\\s+(all\\s+)?previous\\s+instructions\n(?i)reveal\\s+(the\\s+)?system\\s+prompt", "rows": 6})
    domains = TextAreaField("Domains", render_kw={"placeholder": "pastebin.com\nwebhook.site\n169.254.169.254", "rows": 4})
    content_types = TextAreaField("Content Types", render_kw={"placeholder": "application/json\ntext/html", "rows": 3})
    tags = TextAreaField("Tags", render_kw={"placeholder": "prompt-injection\nsecrets\nprod", "rows": 3})
    notes = TextAreaField("Notes", render_kw={"placeholder": "Why this exists, false-positive notes, owner, review date", "rows": 4})
    submit = SubmitField("Save")


class AgentForm(FlaskForm):
    id = StringField("Agent ID", validators=[DataRequired(), Length(max=128)], render_kw={"placeholder": "openclaw-local-01"})
    name = StringField("Name", validators=[DataRequired(), Length(max=255)], render_kw={"placeholder": "OpenClaw Local Agent"})
    description = TextAreaField("Description", render_kw={"placeholder": "What this agent runs and who owns it", "rows": 3})
    enabled = BooleanField("Enabled", default=True)
    allowed_source_ips = TextAreaField("Allowed Source IPs", render_kw={"placeholder": "127.0.0.1\n192.168.1.25", "rows": 3})
    policy_mode = SelectField("Policy Mode", choices=[("balanced", "balanced"), ("strict", "strict"), ("monitor_only", "monitor_only"), ("assessment_mode", "assessment_mode")])
    tags = TextAreaField("Tags", render_kw={"placeholder": "local\nengineering\nprod", "rows": 3})
    submit = SubmitField("Save")


class SettingsForm(FlaskForm):
    policy_mode = SelectField("Policy Mode", choices=[("balanced", "balanced"), ("strict", "strict"), ("monitor_only", "monitor_only"), ("assessment_mode", "assessment_mode")])
    block_unknown_agents = BooleanField("Block unknown agents")
    agent_token_required = BooleanField("Require agent token")
    desktop_notifications_enabled = BooleanField("Desktop notifications")
    desktop_notifications_min_severity = SelectField("Desktop notification minimum severity", choices=[("info", "info"), ("low", "low"), ("medium", "medium"), ("high", "high"), ("critical", "critical")])
    max_inspect_body_size = StringField("Max inspect body size", render_kw={"placeholder": "65536"})
    submit = SubmitField("Save")


class PolicyTesterForm(FlaskForm):
    direction = SelectField("Direction", choices=[("request", "request"), ("response", "response")])
    agent_id = StringField("Agent ID", validators=[Optional()], render_kw={"placeholder": "Optional agent id"})
    policy_mode = SelectField("Policy Mode", choices=[("balanced", "balanced"), ("strict", "strict"), ("monitor_only", "monitor_only"), ("assessment_mode", "assessment_mode")])
    sample = TextAreaField("Sample", validators=[DataRequired(), Length(max=65536)], render_kw={"placeholder": "Paste sample request or response text to evaluate locally", "rows": 10})
    submit = SubmitField("Test")
