"""Command-line entry point: `authenticated-ports {useradd,deluser,serve}`."""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import secrets
import signal
import sys
import threading
import time
from pathlib import Path

from .audit import AuditLog
from .auth import AuthService
from .backends.upnp import UpnpBackend
from .config import AppConfig, load_mappings
from .manager import MappingManager
from .session import SessionStore
from .state import StateStore

log = logging.getLogger("authenticated_ports")


def _bootstrap_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


# --- useradd / deluser ----------------------------------------------------

def _cmd_useradd(args: argparse.Namespace) -> int:
    auth = AuthService(args.credentials)
    pw = args.password_stdin and sys.stdin.readline().rstrip("\n")
    if not pw:
        pw = getpass.getpass("Password: ")
        pw2 = getpass.getpass("Confirm:  ")
        if pw != pw2:
            print("Passwords do not match.", file=sys.stderr)
            return 2
    if len(pw) < 8:
        print("Refusing: password must be at least 8 characters.", file=sys.stderr)
        return 2
    created = auth.set_user(args.username, pw, role=args.role)
    action = "created" if created else "updated"
    print(f"{action} user {args.username!r} (role={args.role}) in {args.credentials}")
    return 0


def _cmd_deluser(args: argparse.Namespace) -> int:
    auth = AuthService(args.credentials)
    ok = auth.delete_user(args.username)
    print(f"{'deleted' if ok else 'not found'}: {args.username}")
    return 0 if ok else 1


# --- serve ----------------------------------------------------------------

def _cmd_serve(args: argparse.Namespace) -> int:
    cfg = AppConfig.load(args.config)
    for attr, override in (
        ("credentials_path", args.credentials),
        ("mappings_path", args.mappings),
        ("listen_host", args.host),
        ("listen_port", args.port),
        ("tls_cert", args.cert),
        ("tls_key", args.key),
        ("behind_proxy", args.behind_proxy),
        ("cookie_secure", args.cookie_secure),
    ):
        if override is not None:
            setattr(cfg, attr, override)

    if cfg.secret_key is None:
        cfg.secret_key = secrets.token_urlsafe(32)

    _bootstrap_logging(args.log_level)

    audit = AuditLog(cfg.audit_log_path)
    auth = AuthService(
        cfg.credentials_path,
        lockout_threshold=cfg.lockout_threshold,
        lockout_window_seconds=cfg.lockout_window_seconds,
    )
    mappings = load_mappings(cfg.mappings_path)
    state = StateStore(cfg.state_path)
    sessions = SessionStore(idle_timeout_seconds=cfg.idle_timeout_seconds)
    backend = UpnpBackend(prefer=args.backend_prefer)
    manager = MappingManager(
        backend=backend, mappings=mappings, state=state,
        audit=audit, description_prefix=cfg.description_prefix,
    )
    manager.start()

    # Background sweeper: idle-timed-out sessions get their mappings closed.
    stop_flag = threading.Event()

    def sweep_loop():
        while not stop_flag.wait(min(30, max(5, cfg.idle_timeout_seconds // 4))):
            for sid in sessions.sweep_expired():
                removed = manager.cleanup_session(sid, reason="idle_timeout")
                audit.event("session_expired", session_id=sid, mappings_closed=removed)

    sweeper = threading.Thread(target=sweep_loop, daemon=True, name="ap-sweeper")
    sweeper.start()

    # Graceful shutdown: close every open mapping before exiting.
    def _handle_shutdown(signum, _frame):
        log.info("shutdown signal %s received", signum)
        stop_flag.set()
        manager.shutdown(reason=f"signal_{signum}")
        os._exit(0)

    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)

    from .app import create_app
    app = create_app(
        config=cfg, auth=auth, mappings=mappings,
        manager=manager, sessions=sessions, audit=audit,
    )

    ssl_context = None
    if cfg.tls_cert and cfg.tls_key:
        ssl_context = (cfg.tls_cert, cfg.tls_key)
        log.info("TLS enabled: cert=%s key=%s", cfg.tls_cert, cfg.tls_key)
    elif cfg.behind_proxy:
        log.info("serving plain HTTP; expecting reverse proxy to terminate TLS "
                 "(trusting %s proxy hop[s])", cfg.trusted_proxy_hops)
    else:
        log.warning("TLS disabled and --behind-proxy not set — run behind a "
                    "reverse proxy that terminates HTTPS, or pass --cert/--key.")

    log.info("listening on %s:%s", cfg.listen_host, cfg.listen_port)
    try:
        app.run(
            host=cfg.listen_host, port=cfg.listen_port,
            ssl_context=ssl_context, threaded=True,
            use_reloader=False, debug=False,
        )
    finally:
        stop_flag.set()
        manager.shutdown(reason="server_exit")
    return 0


# --- parser ---------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="authenticated-ports")
    p.add_argument("--log-level", default=os.environ.get("AP_LOG_LEVEL", "INFO"))
    sub = p.add_subparsers(dest="cmd", required=True)

    pu = sub.add_parser("useradd", help="create or replace a user")
    pu.add_argument("username")
    pu.add_argument("--credentials", default=os.environ.get("AP_CREDENTIALS", "credentials.json"))
    pu.add_argument("--role", default="user", choices=("user", "admin"))
    pu.add_argument("--password-stdin", action="store_true",
                    help="read password from stdin (first line)")
    pu.set_defaults(func=_cmd_useradd)

    pd = sub.add_parser("deluser", help="remove a user")
    pd.add_argument("username")
    pd.add_argument("--credentials", default=os.environ.get("AP_CREDENTIALS", "credentials.json"))
    pd.set_defaults(func=_cmd_deluser)

    ps = sub.add_parser("serve", help="run the web app")
    ps.add_argument("--config", default=os.environ.get("AP_CONFIG"))
    ps.add_argument("--credentials", default=os.environ.get("AP_CREDENTIALS"))
    ps.add_argument("--mappings", default=os.environ.get("AP_MAPPINGS"))
    ps.add_argument("--host", default=os.environ.get("AP_LISTEN_HOST"))
    ps.add_argument("--port", type=int, default=(
        int(os.environ["AP_LISTEN_PORT"]) if os.environ.get("AP_LISTEN_PORT") else None
    ))
    ps.add_argument("--cert", default=os.environ.get("AP_TLS_CERT"))
    ps.add_argument("--key", default=os.environ.get("AP_TLS_KEY"))
    ps.add_argument("--behind-proxy", action="store_true",
                    default=(os.environ.get("AP_BEHIND_PROXY", "").lower() in ("1","true","yes")),
                    help="trust X-Forwarded-For/-Proto/-Host from the proxy")
    _cookie_secure_env = os.environ.get("AP_COOKIE_SECURE", "").lower()
    ps.add_argument("--insecure-cookies", dest="cookie_secure",
                    action="store_const", const=False, default=(
                        False if _cookie_secure_env in ("0", "false", "no") else None
                    ),
                    help="drop the Secure flag from cookies (dev / plain-HTTP only; "
                         "NOT needed when the reverse proxy does TLS termination)")
    ps.add_argument("--backend-prefer", choices=("auto","library","cli"), default="auto")
    ps.set_defaults(func=_cmd_serve)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _bootstrap_logging(args.log_level)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
