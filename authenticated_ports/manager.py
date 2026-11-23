"""Owns the backend and tracks which mappings each session has opened.

Also handles startup reconciliation (anything left in state/ from a crash
gets deleted from the gateway) and shutdown cleanup.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Iterable

from .audit import AuditLog
from .backends.base import BackendError, ForwardingBackend
from .config import AllowedMapping, MappingsConfig
from .state import ActiveRecord, StateStore

log = logging.getLogger(__name__)


class MappingError(RuntimeError):
    """Raised for user-visible failures: not allowed, already open, etc."""


@dataclass
class ActiveView:
    mapping: AllowedMapping
    session_id: str
    user: str
    opened_at: float
    external_ip: str


class MappingManager:
    def __init__(
        self,
        backend: ForwardingBackend,
        mappings: MappingsConfig,
        state: StateStore,
        audit: AuditLog,
        description_prefix: str = "authenticated-ports",
    ) -> None:
        self.backend = backend
        self.mappings = mappings
        self.state = state
        self.audit = audit
        self.description_prefix = description_prefix
        self._lock = threading.RLock()
        self._active: dict[tuple[int, str], ActiveRecord] = {}
        self._session_user: dict[str, str] = {}  # session_id -> user, for audit on cleanup
        self._external_ip: str = ""
        self._ready = False

    # --- lifecycle ------------------------------------------------------

    def start(self) -> None:
        with self._lock:
            info = self.backend.discover()
            try:
                self._external_ip = self.backend.get_external_ip()
            except BackendError:
                self._external_ip = ""
            self._reconcile_from_state()
            self._ready = True
            self.audit.event(
                "startup",
                device=info.get("device", ""),
                external_ip=self._external_ip,
                impl=info.get("impl", ""),
            )

    def shutdown(self, reason: str = "shutdown") -> None:
        with self._lock:
            victims = list(self._active.values())
            for r in victims:
                self._tear_down(r, reason, user=self._session_user.get(r.session_id, ""))
            self._active.clear()
            self._session_user.clear()
            self.state.clear()
            self._ready = False
            self.audit.event("shutdown", reason=reason)

    def _reconcile_from_state(self) -> None:
        orphans = self.state.load()
        for r in orphans:
            try:
                self.backend.remove_mapping(r.external_port, r.protocol)
                self.audit.event(
                    "reconcile_removed",
                    session_id=r.session_id, mapping_id=r.mapping_id,
                    external_port=r.external_port, protocol=r.protocol,
                )
            except BackendError as e:
                log.warning("reconcile: could not remove %s/%s: %s",
                            r.protocol, r.external_port, e)
        self.state.clear()

    # --- queries --------------------------------------------------------

    @property
    def external_ip(self) -> str:
        return self._external_ip

    def refresh_external_ip(self) -> str:
        try:
            self._external_ip = self.backend.get_external_ip()
        except BackendError as e:
            log.warning("could not refresh external IP: %s", e)
        return self._external_ip

    def allowed(self) -> list[AllowedMapping]:
        return list(self.mappings.mappings)

    def active_for_session(self, session_id: str) -> list[ActiveRecord]:
        with self._lock:
            return [r for r in self._active.values() if r.session_id == session_id]

    def status_for_session(self, session_id: str) -> dict[str, bool]:
        """mapping_id -> True if this session has it open."""
        with self._lock:
            on = {r.mapping_id for r in self._active.values() if r.session_id == session_id}
            return {m.id: (m.id in on) for m in self.mappings.mappings}

    def is_externally_active(self, mapping_id: str) -> str | None:
        """Return the session that owns this mapping id, or None."""
        with self._lock:
            for r in self._active.values():
                if r.mapping_id == mapping_id:
                    return r.session_id
            return None

    # --- state-changing operations -------------------------------------

    def _desc(self, session_id: str, mapping_id: str) -> str:
        return f"{self.description_prefix}:{session_id[:8]}:{mapping_id}"

    def activate(self, session_id: str, user: str, mapping_id: str) -> ActiveRecord:
        with self._lock:
            m = self.mappings.by_id(mapping_id)
            if m is None:
                raise MappingError(f"mapping {mapping_id!r} is not in the allowlist")
            owner = self.is_externally_active(mapping_id)
            if owner is not None:
                if owner == session_id:
                    raise MappingError("already active")
                raise MappingError("already open by another session")
            desc = self._desc(session_id, mapping_id)
            try:
                self.backend.add_mapping(
                    m.external_port, m.protocol,
                    m.internal_host, m.internal_port,
                    m.lease_seconds, desc,
                )
            except BackendError as e:
                self.audit.event(
                    "activate_failed",
                    user=user, session_id=session_id,
                    mapping_id=mapping_id, error=str(e),
                )
                raise MappingError(f"gateway rejected mapping: {e}") from e
            rec = ActiveRecord(
                session_id=session_id, mapping_id=mapping_id,
                external_port=m.external_port, protocol=m.protocol,
                internal_host=m.internal_host, internal_port=m.internal_port,
                lease_seconds=m.lease_seconds, opened_at=time.time(),
                description=desc,
            )
            self._active[(m.external_port, m.protocol)] = rec
            self._session_user[session_id] = user
            self._persist()
            self.audit.event(
                "mapping_activate",
                user=user, session_id=session_id,
                mapping_id=mapping_id, external_port=m.external_port,
                protocol=m.protocol, internal_host=m.internal_host,
                internal_port=m.internal_port, lease_seconds=m.lease_seconds,
            )
            return rec

    def deactivate(self, session_id: str, user: str, mapping_id: str) -> None:
        with self._lock:
            target: ActiveRecord | None = None
            for r in self._active.values():
                if r.session_id == session_id and r.mapping_id == mapping_id:
                    target = r
                    break
            if target is None:
                raise MappingError("mapping is not active for this session")
            self._tear_down(target, reason="user", user=user)
            del self._active[(target.external_port, target.protocol)]
            self._persist()

    def cleanup_session(self, session_id: str, reason: str) -> int:
        """Remove every mapping owned by the session. Returns the count
        removed. Safe to call for a session with no mappings."""
        with self._lock:
            victims = [
                r for r in self._active.values() if r.session_id == session_id
            ]
            user = self._session_user.pop(session_id, "")
            for r in victims:
                self._tear_down(r, reason=reason, user=user)
                del self._active[(r.external_port, r.protocol)]
            if victims:
                self._persist()
            return len(victims)

    def _tear_down(self, r: ActiveRecord, reason: str, user: str) -> None:
        try:
            self.backend.remove_mapping(r.external_port, r.protocol)
            self.audit.event(
                "mapping_deactivate",
                user=user, session_id=r.session_id,
                mapping_id=r.mapping_id,
                external_port=r.external_port, protocol=r.protocol,
                reason=reason,
            )
        except BackendError as e:
            self.audit.event(
                "mapping_deactivate_failed",
                user=user, session_id=r.session_id,
                mapping_id=r.mapping_id,
                external_port=r.external_port, protocol=r.protocol,
                error=str(e), reason=reason,
            )
            log.warning("teardown: %s/%s failed: %s",
                        r.protocol, r.external_port, e)

    def _persist(self) -> None:
        self.state.save(list(self._active.values()))
