"""Server-side session store.

A session cookie carries only a random id; all session state (user,
activity timestamps, CSRF token) lives here in memory. Suitable for the
single-process self-hosted app the project targets; not for multi-worker
deployments.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field


SESSION_ID_BYTES = 32
CSRF_TOKEN_BYTES = 32


@dataclass
class SessionData:
    id: str
    user: str
    role: str
    created_at: float
    last_activity: float
    csrf_token: str


class SessionStore:
    def __init__(self, idle_timeout_seconds: int) -> None:
        self.idle_timeout = idle_timeout_seconds
        self._lock = threading.RLock()
        self._sessions: dict[str, SessionData] = {}

    def create(self, user: str, role: str = "user") -> SessionData:
        with self._lock:
            sid = secrets.token_urlsafe(SESSION_ID_BYTES)
            now = time.time()
            s = SessionData(
                id=sid, user=user, role=role,
                created_at=now, last_activity=now,
                csrf_token=secrets.token_urlsafe(CSRF_TOKEN_BYTES),
            )
            self._sessions[sid] = s
            return s

    def touch(self, session_id: str) -> SessionData | None:
        """Return the session if still valid (and update last_activity);
        otherwise, if it expired, drop it and return None."""
        with self._lock:
            s = self._sessions.get(session_id)
            if s is None:
                return s
            now = time.time()
            if now - s.last_activity > self.idle_timeout:
                self._sessions.pop(session_id, None)
                return None
            s.last_activity = now
            return s

    def get(self, session_id: str) -> SessionData | None:
        with self._lock:
            return self._sessions.get(session_id)

    def destroy(self, session_id: str) -> SessionData | None:
        with self._lock:
            return self._sessions.pop(session_id, None)

    def sweep_expired(self) -> list[str]:
        """Return ids of sessions that have been idle too long. Caller
        decides what to do with them (e.g., clean up mappings, log)."""
        now = time.time()
        expired: list[str] = []
        with self._lock:
            for sid, s in list(self._sessions.items()):
                if now - s.last_activity > self.idle_timeout:
                    expired.append(sid)
                    del self._sessions[sid]
        return expired

    def all_ids(self) -> list[str]:
        with self._lock:
            return list(self._sessions.keys())
