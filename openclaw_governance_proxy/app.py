from __future__ import annotations

import csv
import json
from io import StringIO

from flask import Flask, Response, abort, flash, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash

from .auth import check_password, create_user, login_manager, record_login_attempt, regenerate_session, too_many_login_attempts
from .config import Config
from .database import db, init_app_db
from .decorators import admin_required, auditor_or_admin, viewer_allowed
from .forms import AgentForm, LoginForm, PolicyTesterForm, RuleForm, SettingsForm, UserForm
from .logging_jsonl import setup_logging, write_jsonl
from .models import AgentProfile, AgentTag, ProxyEventIndex, Rule, RuleChangeHistory, Setting, UIAuditEvent, User, utcnow
from .pagination import paginate
from .policy import evaluate_policy
from .redaction import redact_text
from .rules import audit_rule_change, export_rules_yaml, load_active_rules, rule_to_dict, validate_rule_payload
from .security_headers import install_security_headers
from .stats import dashboard_stats
from .utils import escape_snippet, json_dumps_safe, load_json_list
from .agent_identity import create_agent_record, rotate_agent_token

csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)


def create_app(config_object=Config) -> Flask:
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.from_object(config_object)
    setup_logging()
    init_app_db(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    install_security_headers(app)
    register_routes(app)
    register_errors(app)
    return app


def audit(event: str, result: str = "success", object_type: str = "", object_id: str = "", agent_id: str = "", details: dict | None = None, severity: str = "info") -> None:
    actor = current_user.username if current_user.is_authenticated else "anonymous"
    role = current_user.role if current_user.is_authenticated else ""
    item = UIAuditEvent(actor=actor, role=role, source_ip=request.remote_addr or "", event=event, object_type=object_type, object_id=object_id, agent_id=agent_id, result=result, severity=severity, details_json=json_dumps_safe(details or {}), request_id=request.headers.get("X-Request-ID", ""))
    db.session.add(item)
    db.session.commit()
    write_jsonl("ui_audit_events.jsonl", {"event": event, "actor": actor, "result": result, "object_type": object_type, "object_id": object_id, "agent_id": agent_id, "details": details or {}})


def lines_to_json(text: str) -> str:
    return json.dumps([x.strip() for x in (text or "").splitlines() if x.strip()])


def register_routes(app: Flask) -> None:
    @app.context_processor
    def context():
        settings = {s.key: s.value for s in Setting.query.all()}
        return {"settings": settings, "version": "0.1.0"}

    @app.route("/")
    @viewer_allowed
    def dashboard():
        return render_template("dashboard.html", stats=dashboard_stats(), recent=ProxyEventIndex.query.order_by(ProxyEventIndex.timestamp.desc()).limit(10).all())

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per 10 minutes")
    def login():
        if User.query.count() == 0:
            flash("No admin exists. Run scripts/create_admin.py before first login.", "warning")
        form = LoginForm()
        if form.validate_on_submit():
            if too_many_login_attempts(form.username.data):
                record_login_attempt(form.username.data, False)
                audit("rate_limited", "blocked", details={"target": "login"})
                flash("Invalid username or password.", "danger")
                return render_template("login.html", form=form), 429
            user = User.query.filter_by(username=form.username.data).first()
            if user and user.enabled and check_password(user, form.password.data):
                regenerate_session()
                login_user(user)
                user.failed_login_count = 0
                user.last_login_at = utcnow()
                db.session.commit()
                record_login_attempt(form.username.data, True)
                audit("login_success")
                return redirect(url_for("dashboard"))
            if user:
                user.failed_login_count += 1
                db.session.commit()
            record_login_attempt(form.username.data, False)
            audit("login_failed", "failed", details={"username": form.username.data}, severity="medium")
            flash("Invalid username or password.", "danger")
        return render_template("login.html", form=form)

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        audit("logout")
        logout_user()
        session.clear()
        return redirect(url_for("login"))

    @app.route("/events")
    @viewer_allowed
    def events():
        q = ProxyEventIndex.query
        for attr in ["agent_id", "severity", "action", "rule_id", "direction", "request_id"]:
            val = request.args.get(attr)
            if val:
                q = q.filter(getattr(ProxyEventIndex, attr) == val)
        if request.args.get("host"):
            q = q.filter(ProxyEventIndex.host.contains(request.args["host"]))
        return render_template("events.html", page=paginate(q.order_by(ProxyEventIndex.timestamp.desc()), request.args))

    @app.route("/events/<int:event_id>")
    @viewer_allowed
    def event_detail(event_id: int):
        return render_template("event_detail.html", event=ProxyEventIndex.query.get_or_404(event_id), escape_snippet=escape_snippet)

    @app.route("/audit")
    @auditor_or_admin
    def audit_log():
        q = UIAuditEvent.query
        for attr in ["actor", "event", "result", "object_type", "object_id", "agent_id", "source_ip", "request_id"]:
            val = request.args.get(attr)
            if val:
                q = q.filter(getattr(UIAuditEvent, attr) == val)
        return render_template("audit.html", page=paginate(q.order_by(UIAuditEvent.timestamp.desc()), request.args))

    @app.route("/audit/<int:audit_id>")
    @auditor_or_admin
    def audit_detail(audit_id: int):
        return render_template("audit_detail.html", event=UIAuditEvent.query.get_or_404(audit_id))

    @app.route("/audit/export", methods=["POST"])
    @auditor_or_admin
    @limiter.limit("5 per hour")
    def audit_export():
        rows = UIAuditEvent.query.order_by(UIAuditEvent.timestamp.desc()).limit(1000).all()
        out = StringIO()
        writer = csv.writer(out)
        writer.writerow(["timestamp", "actor", "event", "result", "object_type", "object_id", "agent_id", "request_id"])
        for r in rows:
            writer.writerow([r.timestamp, r.actor, r.event, r.result, r.object_type, r.object_id, r.agent_id, r.request_id])
        audit("audit_exported")
        return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=audit.csv"})

    @app.route("/rules")
    @viewer_allowed
    def rules():
        q = Rule.query.filter(Rule.deleted_at.is_(None))
        if request.args.get("search"):
            term = f"%{request.args['search']}%"
            q = q.filter(db.or_(Rule.id.like(term), Rule.name.like(term), Rule.description.like(term)))
        for attr in ["severity", "action", "direction", "scope", "agent_id", "updated_by"]:
            val = request.args.get(attr)
            if val:
                q = q.filter(getattr(Rule, attr) == val)
        if request.args.get("enabled") in {"true", "false"}:
            q = q.filter(Rule.enabled.is_(request.args["enabled"] == "true"))
        return render_template("rules.html", page=paginate(q.order_by(Rule.updated_at.desc()), request.args))

    @app.route("/rules/new", methods=["GET", "POST"])
    @admin_required
    def rule_new():
        form = RuleForm()
        if form.validate_on_submit():
            payload = form.data | {"patterns": [x.strip() for x in form.patterns.data.splitlines() if x.strip()], "domains": [x.strip() for x in form.domains.data.splitlines() if x.strip()], "content_types": [x.strip() for x in form.content_types.data.splitlines() if x.strip()], "tags": [x.strip() for x in form.tags.data.splitlines() if x.strip()]}
            ok, msg = validate_rule_payload(payload)
            if not ok or Rule.query.get(form.id.data):
                flash(msg or "Rule ID already exists.", "danger")
            else:
                rule = Rule(id=form.id.data, name=form.name.data, description=form.description.data, enabled=form.enabled.data, severity=form.severity.data, action=form.action.data, direction=form.direction.data, match_type=form.match_type.data, scope=form.scope.data, agent_id=form.agent_id.data or None, patterns=json.dumps(payload["patterns"]), domains=json.dumps(payload["domains"]), content_types=json.dumps(payload["content_types"]), tags=json.dumps(payload["tags"]), notes=form.notes.data, created_by=current_user.username, updated_by=current_user.username)
                db.session.add(rule)
                audit_rule_change(rule.id, current_user, "created", None, rule_to_dict(rule), request.remote_addr or "", request.user_agent.string)
                db.session.commit()
                audit("rule_created", object_type="rule", object_id=rule.id)
                flash("Rule created.", "success")
                return redirect(url_for("rules"))
        return render_template("rule_edit.html", form=form, title="Create Rule")

    @app.route("/rules/<rule_id>")
    @viewer_allowed
    def rule_view(rule_id: str):
        return render_template("rule_view.html", rule=Rule.query.get_or_404(rule_id), load_json_list=load_json_list)

    @app.route("/rules/<rule_id>/edit", methods=["GET", "POST"])
    @admin_required
    def rule_edit(rule_id: str):
        rule = Rule.query.get_or_404(rule_id)
        form = RuleForm(obj=rule)
        if request.method == "GET":
            form.patterns.data = "\n".join(load_json_list(rule.patterns))
            form.domains.data = "\n".join(load_json_list(rule.domains))
            form.content_types.data = "\n".join(load_json_list(rule.content_types))
            form.tags.data = "\n".join(load_json_list(rule.tags))
        if form.validate_on_submit():
            old = rule_to_dict(rule)
            payload = form.data | {"patterns": [x.strip() for x in form.patterns.data.splitlines() if x.strip()], "domains": [x.strip() for x in form.domains.data.splitlines() if x.strip()], "content_types": [x.strip() for x in form.content_types.data.splitlines() if x.strip()], "tags": [x.strip() for x in form.tags.data.splitlines() if x.strip()]}
            ok, msg = validate_rule_payload(payload, existing_id=rule_id)
            if not ok:
                flash(msg, "danger")
            else:
                for attr in ["name", "description", "enabled", "severity", "action", "direction", "match_type", "scope", "agent_id", "notes"]:
                    setattr(rule, attr, getattr(form, attr).data or None if attr == "agent_id" else getattr(form, attr).data)
                rule.patterns, rule.domains, rule.content_types, rule.tags = json.dumps(payload["patterns"]), json.dumps(payload["domains"]), json.dumps(payload["content_types"]), json.dumps(payload["tags"])
                rule.updated_by = current_user.username
                audit_rule_change(rule.id, current_user, "updated", old, rule_to_dict(rule), request.remote_addr or "", request.user_agent.string)
                db.session.commit()
                audit("rule_updated", object_type="rule", object_id=rule.id)
                flash("Rule updated.", "success")
                return redirect(url_for("rule_view", rule_id=rule.id))
        return render_template("rule_edit.html", form=form, title="Edit Rule")

    @app.route("/rules/<rule_id>/<action>", methods=["POST"])
    @admin_required
    def rule_action(rule_id: str, action: str):
        rule = Rule.query.get_or_404(rule_id)
        old = rule_to_dict(rule)
        if action == "enable":
            rule.enabled = True
        elif action == "disable":
            rule.enabled = False
        elif action == "delete":
            rule.deleted_at = utcnow()
        elif action == "clone":
            clone = Rule(**{k: getattr(rule, k) for k in ["name", "description", "enabled", "severity", "action", "direction", "match_type", "scope", "agent_id", "patterns", "domains", "content_types", "tags", "notes"]})
            clone.id = rule.id + "_copy"
            clone.name = rule.name + " Copy"
            clone.created_by = current_user.username
            clone.updated_by = current_user.username
            db.session.add(clone)
            audit_rule_change(rule.id, current_user, "cloned", old, rule_to_dict(clone), request.remote_addr or "", request.user_agent.string)
            db.session.commit()
            audit("rule_cloned", object_type="rule", object_id=rule.id)
            return redirect(url_for("rule_edit", rule_id=clone.id))
        else:
            abort(404)
        audit_rule_change(rule.id, current_user, action + "d", old, rule_to_dict(rule), request.remote_addr or "", request.user_agent.string)
        db.session.commit()
        audit(f"rule_{action}d", object_type="rule", object_id=rule.id)
        flash(f"Rule {action}d.", "success")
        return redirect(url_for("rules"))

    @app.route("/rules/export", methods=["POST"])
    @admin_required
    def rules_export():
        audit("rules_exported")
        return Response(export_rules_yaml(), mimetype="application/x-yaml", headers={"Content-Disposition": "attachment; filename=rules.yaml"})

    @app.route("/rules/reload", methods=["POST"])
    @admin_required
    @limiter.limit("10 per hour")
    def rules_reload():
        load_active_rules(db.session)
        audit("rules_reloaded")
        flash("Rules reloaded and compiled.", "success")
        return redirect(url_for("rules"))

    @app.route("/policy-tester", methods=["GET", "POST"])
    @admin_required
    @limiter.limit("30 per hour")
    def policy_tester():
        form = PolicyTesterForm()
        matches = []
        redacted_preview = ""
        if form.validate_on_submit():
            compiled = load_active_rules(db.session)
            matches = evaluate_policy(compiled, direction=form.direction.data, host="tester.local", url="https://tester.local/", body=form.sample.data, agent_id=form.agent_id.data or None, policy_mode=form.policy_mode.data)
            redacted_preview = redact_text(form.sample.data)[:1000]
            audit("rule_tested", object_type="policy_tester")
        return render_template("policy_tester.html", form=form, matches=matches, redacted_preview=redacted_preview)

    @app.route("/agents")
    @viewer_allowed
    def agents():
        q = AgentProfile.query
        if request.args.get("search"):
            term = f"%{request.args['search']}%"
            q = q.filter(db.or_(AgentProfile.id.like(term), AgentProfile.name.like(term)))
        return render_template("agents.html", page=paginate(q.order_by(AgentProfile.updated_at.desc()), request.args))

    @app.route("/agents/new", methods=["GET", "POST"])
    @admin_required
    def agent_new():
        form = AgentForm()
        token = None
        if form.validate_on_submit():
            if AgentProfile.query.get(form.id.data):
                flash("Agent ID already exists.", "danger")
            else:
                agent, token = create_agent_record(db.session, form.id.data, form.name.data, form.description.data, form.policy_mode.data)
                agent.enabled = form.enabled.data
                agent.allowed_source_ips = lines_to_json(form.allowed_source_ips.data)
                db.session.commit()
                for tag in [x.strip() for x in form.tags.data.splitlines() if x.strip()]:
                    db.session.add(AgentTag(agent_id=agent.id, tag=tag))
                db.session.commit()
                audit("agent_created", object_type="agent", object_id=agent.id, agent_id=agent.id)
                return render_template("agent_view.html", agent=agent, tags=form.tags.data.splitlines(), token=token)
        return render_template("agent_edit.html", form=form, title="Create Agent")

    @app.route("/agents/<agent_id>")
    @viewer_allowed
    def agent_view(agent_id: str):
        agent = AgentProfile.query.get_or_404(agent_id)
        tags = [t.tag for t in AgentTag.query.filter_by(agent_id=agent.id).all()]
        recent = ProxyEventIndex.query.filter_by(agent_id=agent.id).order_by(ProxyEventIndex.timestamp.desc()).limit(20).all()
        return render_template("agent_view.html", agent=agent, tags=tags, recent=recent, token=None)

    @app.route("/agents/<agent_id>/edit", methods=["GET", "POST"])
    @admin_required
    def agent_edit(agent_id: str):
        agent = AgentProfile.query.get_or_404(agent_id)
        form = AgentForm(obj=agent)
        if request.method == "GET":
            form.allowed_source_ips.data = "\n".join(load_json_list(agent.allowed_source_ips))
            form.tags.data = "\n".join([t.tag for t in AgentTag.query.filter_by(agent_id=agent.id).all()])
        if form.validate_on_submit():
            agent.name, agent.description, agent.enabled, agent.policy_mode = form.name.data, form.description.data, form.enabled.data, form.policy_mode.data
            agent.allowed_source_ips = lines_to_json(form.allowed_source_ips.data)
            AgentTag.query.filter_by(agent_id=agent.id).delete()
            for tag in [x.strip() for x in form.tags.data.splitlines() if x.strip()]:
                db.session.add(AgentTag(agent_id=agent.id, tag=tag))
            db.session.commit()
            audit("agent_updated", object_type="agent", object_id=agent.id, agent_id=agent.id)
            flash("Agent updated.", "success")
            return redirect(url_for("agent_view", agent_id=agent.id))
        return render_template("agent_edit.html", form=form, title="Edit Agent")

    @app.route("/agents/<agent_id>/<action>", methods=["POST"])
    @admin_required
    @limiter.limit("20 per hour")
    def agent_action(agent_id: str, action: str):
        agent = AgentProfile.query.get_or_404(agent_id)
        token = None
        if action == "enable":
            agent.enabled = True
        elif action == "disable":
            agent.enabled = False
        elif action == "rotate-token":
            token = rotate_agent_token(agent)
        elif action == "delete":
            db.session.delete(agent)
        else:
            abort(404)
        db.session.commit()
        audit(f"agent_{action.replace('-', '_')}", object_type="agent", object_id=agent_id, agent_id=agent_id)
        if token:
            return render_template("agent_view.html", agent=agent, tags=[t.tag for t in AgentTag.query.filter_by(agent_id=agent.id).all()], token=token)
        return redirect(url_for("agents"))

    @app.route("/agents/<agent_id>/events")
    @viewer_allowed
    def agent_events(agent_id: str):
        q = ProxyEventIndex.query.filter_by(agent_id=agent_id).order_by(ProxyEventIndex.timestamp.desc())
        return render_template("agent_events.html", page=paginate(q, request.args), agent_id=agent_id)

    @app.route("/settings", methods=["GET", "POST"])
    @admin_required
    def settings():
        form = SettingsForm()
        current = {s.key: s for s in Setting.query.all()}
        if request.method == "GET":
            for field in ["policy_mode", "max_inspect_body_size", "desktop_notifications_min_severity"]:
                if field in current:
                    getattr(form, field).data = current[field].value
            form.block_unknown_agents.data = current.get("block_unknown_agents") and current["block_unknown_agents"].value == "true"
            form.agent_token_required.data = current.get("agent_token_required") and current["agent_token_required"].value == "true"
            form.desktop_notifications_enabled.data = current.get("desktop_notifications_enabled") and current["desktop_notifications_enabled"].value == "true"
        if form.validate_on_submit():
            values = {
                "policy_mode": form.policy_mode.data,
                "max_inspect_body_size": form.max_inspect_body_size.data,
                "block_unknown_agents": str(form.block_unknown_agents.data).lower(),
                "agent_token_required": str(form.agent_token_required.data).lower(),
                "desktop_notifications_enabled": str(form.desktop_notifications_enabled.data).lower(),
                "desktop_notifications_min_severity": form.desktop_notifications_min_severity.data,
            }
            for k, v in values.items():
                current.setdefault(k, Setting(key=k, value=v)).value = v
                db.session.add(current[k])
            db.session.commit()
            audit("settings_updated")
            flash("Settings saved.", "success")
        return render_template("settings.html", form=form)

    @app.route("/stats")
    @viewer_allowed
    def stats():
        return render_template("stats.html", stats=dashboard_stats())

    @app.route("/users")
    @admin_required
    def users():
        return render_template("users.html", page=paginate(User.query.order_by(User.username), request.args))

    @app.route("/users/new", methods=["GET", "POST"])
    @admin_required
    def user_new():
        form = UserForm()
        if form.validate_on_submit():
            try:
                create_user(form.username.data, form.email.data, form.password.data, form.role.data)
                audit("user_created", object_type="user", object_id=form.username.data)
                flash("User created.", "success")
                return redirect(url_for("users"))
            except Exception as exc:
                flash(str(exc), "danger")
        return render_template("user_edit.html", form=form, title="Create User")

    @app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
    @admin_required
    def user_edit(user_id: int):
        user = User.query.get_or_404(user_id)
        form = UserForm(obj=user)
        if form.validate_on_submit():
            if user.role == "admin" and not form.enabled.data and User.query.filter_by(role="admin", enabled=True).count() <= 1:
                flash("Cannot disable the last admin.", "danger")
            elif user.id == current_user.id and not form.enabled.data:
                flash("Cannot disable your own account.", "danger")
            else:
                user.email, user.role, user.enabled = form.email.data, form.role.data, form.enabled.data
                if form.password.data:
                    user.password_hash = generate_password_hash(form.password.data, method="scrypt")
                    user.session_version += 1
                    audit("password_changed", object_type="user", object_id=user.username)
                db.session.commit()
                audit("user_updated", object_type="user", object_id=user.username)
                return redirect(url_for("users"))
        return render_template("user_edit.html", form=form, title="Edit User")

    @app.route("/openclaw-setup")
    @viewer_allowed
    def openclaw_setup():
        return render_template("openclaw_setup.html")

    @app.route("/ca-certificate")
    @viewer_allowed
    def ca_certificate():
        return render_template("ca_certificate.html")


def register_errors(app: Flask) -> None:
    for code in [400, 401, 403, 404, 429, 500]:
        app.register_error_handler(code, lambda e, code=code: (render_template(f"errors/{code}.html", error=e), code))


app = create_app()
