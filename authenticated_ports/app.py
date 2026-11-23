"""Flask app factory. Server-side sessions + per-request CSRF.

We intentionally do NOT use Flask's signed-cookie session: the cookie
only carries an opaque session id, every other piece of state lives in
SessionStore in memory.
"""

from __future__ import annotations

import hmac
import logging
import secrets
import time
from functools import wraps

from flask import (
    Flask, abort, flash, g, make_response, redirect,
    render_template, request, url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from .audit import AuditLog
from .auth import AuthService
from .config import AppConfig, MappingsConfig, load_mappings
from .manager import MappingManager, MappingError
from .session import SessionStore

log = logging.getLogger(__name__)

SESSION_COOKIE_NAME = "ap_session"


def _client_ip() -> str:
    cfg: AppConfig = g.ap_app_config
    if cfg.behind_proxy:
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.remote_addr or ""


def _require_session():
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    if not sid:
        return None
    store: SessionStore = g.ap_sessions
    return store.touch(sid)


def _check_csrf(session_token: str) -> None:
    token = request.form.get("csrf_token", "")
    if not token or not hmac.compare_digest(token, session_token):
        abort(400, description="CSRF token mismatch")


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kw):
        s = _require_session()
        if s is None:
            return redirect(url_for("login"))
        g.session = s
        return fn(*args, **kw)
    return wrapper


def _cookie_secure() -> bool:
    cfg: AppConfig = g.ap_app_config
    return cfg.cookie_secure


def _clear_session_cookie(resp):
    resp.set_cookie(
        SESSION_COOKIE_NAME, "", expires=0, max_age=0,
        httponly=True, secure=_cookie_secure(), samesite="Strict", path="/",
    )
    return resp


def _set_session_cookie(resp, session_id: str):
    resp.set_cookie(
        SESSION_COOKIE_NAME, session_id,
        httponly=True, secure=_cookie_secure(), samesite="Strict", path="/",
    )
    return resp


def create_app(
    config: AppConfig,
    auth: AuthService,
    mappings: MappingsConfig,
    manager: MappingManager,
    sessions: SessionStore,
    audit: AuditLog,
) -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.secret_key or secrets.token_urlsafe(32)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SECURE"] = config.cookie_secure
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"

    if config.behind_proxy:
        n = max(1, int(config.trusted_proxy_hops))
        app.wsgi_app = ProxyFix(
            app.wsgi_app, x_for=n, x_proto=n, x_host=n, x_port=n,
        )

    @app.before_request
    def _inject():
        g.ap_app_config = config
        g.ap_sessions = sessions
        g.ap_manager = manager
        g.ap_audit = audit
        g.ap_auth = auth

    # -- login -----------------------------------------------------------

    @app.route("/login", methods=["GET", "POST"])
    def login():
        existing = _require_session()
        if existing is not None:
            return redirect(url_for("dashboard"))

        # One-shot CSRF for the login form; store short-lived cookie.
        login_csrf = request.cookies.get("ap_login_csrf") or secrets.token_urlsafe(32)

        if request.method == "POST":
            posted = request.form.get("csrf_token", "")
            if not posted or not hmac.compare_digest(posted, login_csrf):
                abort(400, description="CSRF token mismatch")
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            ip = _client_ip()
            result = auth.verify(username, password)
            if not result.ok:
                audit.event(
                    "login_failure",
                    user=username, remote_addr=ip,
                    reason=result.failure or "unknown",
                )
                time.sleep(0.5)  # modest brute-force damper
                flash(_login_message(result.failure), "error")
                resp = make_response(render_template(
                    "login.html",
                    csrf_token=login_csrf,
                    username=username,
                ))
                _set_login_csrf_cookie(resp, login_csrf)
                return resp
            # Success.
            role = result.user.get("role", "user") if result.user else "user"
            s = sessions.create(username, role=role)
            audit.event("login_success", user=username,
                        session_id=s.id, remote_addr=ip)
            resp = make_response(redirect(url_for("dashboard")))
            _clear_login_csrf_cookie(resp)
            _set_session_cookie(resp, s.id)
            return resp

        # GET
        resp = make_response(render_template(
            "login.html", csrf_token=login_csrf, username="",
        ))
        _set_login_csrf_cookie(resp, login_csrf)
        return resp

    # -- dashboard ------------------------------------------------------

    @app.route("/", methods=["GET"])
    @login_required
    def dashboard():
        s = g.session
        status = manager.status_for_session(s.id)
        rows = []
        active_recs = {r.mapping_id: r for r in manager.active_for_session(s.id)}
        ext_ip = manager.external_ip or "(unknown)"
        for m in manager.allowed():
            rec = active_recs.get(m.id)
            rows.append({
                "mapping": m,
                "active": status.get(m.id, False),
                "connect_string": (
                    f"{ext_ip}:{m.external_port} -> "
                    f"{m.internal_host}:{m.internal_port} ({m.protocol})"
                ) if rec else "",
                "opened_at": rec.opened_at if rec else None,
                "owned_by_other": (
                    manager.is_externally_active(m.id) not in (None, s.id)
                ),
            })
        return render_template(
            "dashboard.html",
            user=s.user, role=s.role,
            external_ip=ext_ip, rows=rows,
            csrf_token=s.csrf_token,
            idle_timeout=config.idle_timeout_seconds,
        )

    # -- activate / deactivate -----------------------------------------

    @app.route("/mappings/<mapping_id>/activate", methods=["POST"])
    @login_required
    def activate(mapping_id):
        s = g.session
        _check_csrf(s.csrf_token)
        try:
            manager.activate(s.id, s.user, mapping_id)
            flash(f"Activated {mapping_id}.", "ok")
        except MappingError as e:
            flash(f"Could not activate {mapping_id}: {e}", "error")
        return redirect(url_for("dashboard"))

    @app.route("/mappings/<mapping_id>/deactivate", methods=["POST"])
    @login_required
    def deactivate(mapping_id):
        s = g.session
        _check_csrf(s.csrf_token)
        try:
            manager.deactivate(s.id, s.user, mapping_id)
            flash(f"Deactivated {mapping_id}.", "ok")
        except MappingError as e:
            flash(f"Could not deactivate {mapping_id}: {e}", "error")
        return redirect(url_for("dashboard"))

    # -- logout --------------------------------------------------------

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        s = g.session
        _check_csrf(s.csrf_token)
        removed = manager.cleanup_session(s.id, reason="logout")
        sessions.destroy(s.id)
        audit.event(
            "logout",
            user=s.user, session_id=s.id,
            remote_addr=_client_ip(), mappings_closed=removed,
        )
        resp = make_response(redirect(url_for("login")))
        return _clear_session_cookie(resp)

    # -- status endpoint (JSON, for liveness / scripts) ----------------

    @app.route("/healthz", methods=["GET"])
    def healthz():
        return {"ok": True, "external_ip": manager.external_ip}

    # -- error handlers ------------------------------------------------

    @app.errorhandler(400)
    def _bad_request(e):
        return (f"400: {getattr(e, 'description', 'bad request')}", 400)

    return app


def _login_message(failure: str | None) -> str:
    return {
        "unknown_user": "Invalid username or password.",
        "bad_password": "Invalid username or password.",
        "bad_hash": "Server configuration error: unsupported password hash.",
        "locked_out": "Too many failed attempts. Try again later.",
    }.get(failure or "", "Invalid username or password.")


def _set_login_csrf_cookie(resp, token: str):
    resp.set_cookie(
        "ap_login_csrf", token,
        httponly=True, secure=_cookie_secure(), samesite="Strict", path="/login",
        max_age=600,
    )


def _clear_login_csrf_cookie(resp):
    resp.set_cookie(
        "ap_login_csrf", "", expires=0, max_age=0,
        httponly=True, secure=_cookie_secure(), samesite="Strict", path="/login",
    )
