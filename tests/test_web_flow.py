"""End-to-end-ish test of the Flask app with the MockIGD and the test
client: login, activate, deactivate, logout-closes-all, CSRF rejected,
lockout, unknown mapping id rejected."""

from __future__ import annotations

import pytest

from authenticated_ports.app import SESSION_COOKIE_NAME, create_app
from authenticated_ports.audit import AuditLog
from authenticated_ports.auth import AuthService
from authenticated_ports.config import AppConfig, MappingsConfig, AllowedMapping
from authenticated_ports.manager import MappingManager
from authenticated_ports.session import SessionStore
from authenticated_ports.state import StateStore
from tests.mock_backend import MockIGD


@pytest.fixture
def app_env(tmp_path):
    cfg = AppConfig(
        idle_timeout_seconds=600,
        lockout_threshold=3,
        lockout_window_seconds=600,
        secret_key="test-secret-key",
    )
    auth = AuthService(tmp_path / "creds.json",
                       lockout_threshold=cfg.lockout_threshold,
                       lockout_window_seconds=cfg.lockout_window_seconds)
    auth.set_user("alice", "hunter2!!")
    mc = MappingsConfig(mappings=[
        AllowedMapping(id="rdp", name="RDP", protocol="tcp",
                       external_port=53389, internal_host="192.168.1.10",
                       internal_port=3389, lease_seconds=600),
        AllowedMapping(id="ssh", name="SSH", protocol="tcp",
                       external_port=52222, internal_host="192.168.1.11",
                       internal_port=22, lease_seconds=600),
    ])
    be = MockIGD()
    audit = AuditLog(tmp_path / "audit.log")
    state = StateStore(tmp_path / "active.json")
    mgr = MappingManager(backend=be, mappings=mc, state=state, audit=audit)
    mgr.start()
    sess = SessionStore(idle_timeout_seconds=cfg.idle_timeout_seconds)
    app = create_app(config=cfg, auth=auth, mappings=mc,
                     manager=mgr, sessions=sess, audit=audit)
    # We serve over plain HTTP in tests; Flask's test client doesn't
    # enforce the Secure cookie flag, so this is fine.
    app.testing = True
    return app, be, mgr, sess, auth


def _get_login_csrf(client):
    r = client.get("/login")
    assert r.status_code == 200
    html = r.data.decode()
    import re
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "no csrf_token in login form"
    return m.group(1)


def _login(client, username="alice", password="hunter2!!"):
    tok = _get_login_csrf(client)
    r = client.post("/login", data={
        "csrf_token": tok, "username": username, "password": password,
    }, follow_redirects=False)
    return r


def _dashboard_csrf(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 200
    import re
    m = re.search(r'name="csrf_token" value="([^"]+)"', r.data.decode())
    assert m
    return m.group(1)


def test_login_redirects_and_sets_cookie(app_env):
    app, *_ = app_env
    with app.test_client() as c:
        r = _login(c)
        assert r.status_code == 302
        assert "/" in r.headers["Location"]
        assert SESSION_COOKIE_NAME in {h[0] for h in [
            (ck.key,) for ck in c._cookies.values()
        ]}


def test_bad_password_does_not_create_session(app_env):
    app, *_ = app_env
    with app.test_client() as c:
        r = _login(c, password="wrong")
        assert r.status_code == 200  # re-renders login page
        # no session cookie set
        assert all(ck.key != SESSION_COOKIE_NAME or not ck.value
                   for ck in c._cookies.values())


def test_login_lockout(app_env):
    app, *_ = app_env
    with app.test_client() as c:
        for _ in range(3):
            _login(c, password="wrong")
        r = _login(c, password="hunter2!!")  # correct, but locked
        assert r.status_code == 200
        assert b"Too many failed attempts" in r.data


def test_activate_then_deactivate_via_http(app_env):
    app, be, mgr, *_ = app_env
    with app.test_client() as c:
        _login(c)
        tok = _dashboard_csrf(c)
        r = c.post("/mappings/rdp/activate", data={"csrf_token": tok})
        assert r.status_code == 302
        assert any(m.external_port == 53389 for m in be.list_mappings())
        tok = _dashboard_csrf(c)
        r = c.post("/mappings/rdp/deactivate", data={"csrf_token": tok})
        assert r.status_code == 302
        assert be.list_mappings() == []


def test_activate_rejects_unknown_mapping_id(app_env):
    app, be, mgr, *_ = app_env
    with app.test_client() as c:
        _login(c)
        tok = _dashboard_csrf(c)
        r = c.post("/mappings/not-a-real-id/activate",
                   data={"csrf_token": tok}, follow_redirects=True)
        assert r.status_code == 200
        # flash message surfaces the error
        assert b"not in the allowlist" in r.data
        # nothing created on the device
        assert be.list_mappings() == []


def test_csrf_required_on_state_change(app_env):
    app, be, *_ = app_env
    with app.test_client() as c:
        _login(c)
        r = c.post("/mappings/rdp/activate", data={})  # missing token
        assert r.status_code == 400
        assert be.list_mappings() == []


def test_logout_closes_all_session_mappings(app_env):
    app, be, mgr, *_ = app_env
    with app.test_client() as c:
        _login(c)
        tok = _dashboard_csrf(c)
        c.post("/mappings/rdp/activate", data={"csrf_token": tok})
        tok = _dashboard_csrf(c)
        c.post("/mappings/ssh/activate", data={"csrf_token": tok})
        assert len(be.list_mappings()) == 2
        tok = _dashboard_csrf(c)
        r = c.post("/logout", data={"csrf_token": tok}, follow_redirects=False)
        assert r.status_code == 302
        assert be.list_mappings() == []


def test_unauthenticated_access_redirects_to_login(app_env):
    app, *_ = app_env
    with app.test_client() as c:
        r = c.get("/", follow_redirects=False)
        assert r.status_code == 302
        assert "/login" in r.headers["Location"]


def test_healthz_is_public(app_env):
    app, *_ = app_env
    with app.test_client() as c:
        r = c.get("/healthz")
        assert r.status_code == 200
        assert r.json["ok"] is True


def test_behind_proxy_plain_http_flow_without_secure_flag(tmp_path):
    """Reverse-proxy deployment: app serves plain HTTP, cookies carry
    no Secure flag, and X-Forwarded-For is trusted for audit logs."""
    cfg = AppConfig(
        idle_timeout_seconds=600, lockout_threshold=5, lockout_window_seconds=600,
        secret_key="test", behind_proxy=True, cookie_secure=False,
    )
    auth = AuthService(tmp_path / "creds.json")
    auth.set_user("alice", "hunter2!!")
    mc = MappingsConfig(mappings=[
        AllowedMapping(id="rdp", name="RDP", protocol="tcp",
                       external_port=53389, internal_host="192.168.1.10",
                       internal_port=3389, lease_seconds=600),
    ])
    be = MockIGD()
    state = StateStore(tmp_path / "active.json")
    audit = AuditLog(tmp_path / "audit.log")
    mgr = MappingManager(backend=be, mappings=mc, state=state, audit=audit)
    mgr.start()
    sess = SessionStore(idle_timeout_seconds=cfg.idle_timeout_seconds)
    app = create_app(config=cfg, auth=auth, mappings=mc,
                     manager=mgr, sessions=sess, audit=audit)
    app.testing = True
    with app.test_client() as c:
        # Simulate the proxy adding X-Forwarded-* headers.
        headers = {
            "X-Forwarded-For": "203.0.113.42",
            "X-Forwarded-Proto": "https",
        }
        r = c.get("/login", headers=headers)
        assert r.status_code == 200
        # Set-Cookie must NOT carry Secure in this mode.
        cookie_hdrs = r.headers.getlist("Set-Cookie")
        assert cookie_hdrs
        assert not any("Secure" in h for h in cookie_hdrs)
        import re
        tok = re.search(r'name="csrf_token" value="([^"]+)"', r.data.decode()).group(1)
        r = c.post("/login", headers=headers, data={
            "csrf_token": tok, "username": "alice", "password": "hunter2!!",
        })
        assert r.status_code == 302
        # Audit log should record the forwarded IP, not the loopback.
        txt = (tmp_path / "audit.log").read_text()
        assert "203.0.113.42" in txt
