"""Append-only audit log.

Each line is one JSON object: timestamp, event, user, session_short, details.
Sessions are logged by a short prefix of the session id so logs stay
useful without turning into credential-adjacent material.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def _short_session(session_id: str | None) -> str:
    if not session_id:
        return ""
    return session_id[:8]


class AuditLog:
    def __init__(self, path: str | os.PathLike[str] | None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def event(
        self,
        event: str,
        *,
        user: str | None = None,
        session_id: str | None = None,
        remote_addr: str | None = None,
        **details: Any,
    ) -> None:
        row = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime()),
            "event": event,
            "user": user or "",
            "session": _short_session(session_id),
            "remote_addr": remote_addr or "",
            **{k: v for k, v in details.items() if v is not None},
        }
        line = json.dumps(row, separators=(",", ":"))
        if self.path:
            with self._lock:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
        # Also emit to the app logger at INFO so operators see it live.
        log.info("audit %s", line)
