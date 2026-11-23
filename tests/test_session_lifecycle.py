"""Session lifecycle: activate / deactivate / logout-closes-all /
idle-sweep / startup reconciliation. All against the MockIGD."""

from __future__ import annotations

import json
import time

import pytest

from authenticated_ports.audit import AuditLog
from authenticated_ports.config import MappingsConfig, AllowedMapping
from authenticated_ports.manager import MappingManager, MappingError
from authenticated_ports.session import SessionStore
from authenticated_ports.state import StateStore
from tests.mock_backend import MockIGD


def _mc():
    return MappingsConfig(mappings=[
        AllowedMapping(id="rdp", name="RDP", protocol="tcp",
                       external_port=53389, internal_host="192.168.1.10",
                       internal_port=3389, lease_seconds=600),
        AllowedMapping(id="ssh", name="SSH", protocol="tcp",
                       external_port=52222, internal_host="192.168.1.11",
                       internal_port=22, lease_seconds=600),
        AllowedMapping(id="udp", name="UDP", protocol="udp",
                       external_port=55555, internal_host="192.168.1.12",
                       internal_port=27015, lease_seconds=600),
    ])


def _mgr(tmp_path, backend=None, mappings=None):
    be = backend or MockIGD()
    mc = mappings or _mc()
    state = StateStore(tmp_path / "active.json")
    audit = AuditLog(tmp_path / "audit.log")
    return MappingManager(backend=be, mappings=mc, state=state, audit=audit), be


def test_activate_and_deactivate(tmp_path):
    m, be = _mgr(tmp_path)
    m.start()
    rec = m.activate("sess-1", "alice", "rdp")
    assert rec.external_port == 53389
    assert any(x.external_port == 53389 for x in be.list_mappings())
    m.deactivate("sess-1", "alice", "rdp")
    assert be.list_mappings() == []


def test_activate_rejects_unknown_mapping(tmp_path):
    m, _ = _mgr(tmp_path)
    m.start()
    with pytest.raises(MappingError, match="not in the allowlist"):
        m.activate("sess-1", "alice", "ghost")


def test_activate_twice_in_same_session_is_rejected(tmp_path):
    m, _ = _mgr(tmp_path)
    m.start()
    m.activate("sess-1", "alice", "rdp")
    with pytest.raises(MappingError, match="already active"):
        m.activate("sess-1", "alice", "rdp")


def test_activate_rejected_if_another_session_owns_it(tmp_path):
    m, _ = _mgr(tmp_path)
    m.start()
    m.activate("sess-1", "alice", "rdp")
    with pytest.raises(MappingError, match="another session"):
        m.activate("sess-2", "bob", "rdp")


def test_logout_closes_all_session_mappings(tmp_path):
    m, be = _mgr(tmp_path)
    m.start()
    m.activate("sess-1", "alice", "rdp")
    m.activate("sess-1", "alice", "ssh")
    m.activate("sess-2", "bob", "udp")
    assert len(be.list_mappings()) == 3
    removed = m.cleanup_session("sess-1", reason="logout")
    assert removed == 2
    remaining = be.list_mappings()
    assert len(remaining) == 1
    assert remaining[0].external_port == 55555  # bob's UDP survives


def test_shutdown_closes_everything(tmp_path):
    m, be = _mgr(tmp_path)
    m.start()
    m.activate("s1", "a", "rdp")
    m.activate("s2", "b", "ssh")
    m.shutdown(reason="test")
    assert be.list_mappings() == []


def test_state_persists_across_restart_and_reconciles(tmp_path):
    be = MockIGD()
    m1, _ = _mgr(tmp_path, backend=be)
    m1.start()
    m1.activate("s1", "a", "rdp")
    m1.activate("s1", "a", "ssh")
    assert len(be.list_mappings()) == 2
    # Simulate crash: state file is on disk, manager drops. Mapping
    # still present on device.
    state_path = tmp_path / "active.json"
    assert state_path.exists()
    assert len(json.loads(state_path.read_text())["active"]) == 2
    # Re-create manager (same backend instance = same device state).
    m2, _ = _mgr(tmp_path, backend=be)
    m2.start()
    # Reconcile should have deleted the orphan mappings.
    assert be.list_mappings() == []
    # And state file is now cleared.
    assert json.loads(state_path.read_text())["active"] == []


def test_idle_sweeper_cleans_up_mappings(tmp_path):
    m, be = _mgr(tmp_path)
    m.start()
    store = SessionStore(idle_timeout_seconds=1)
    s = store.create("alice", role="user")
    m.activate(s.id, "alice", "rdp")
    assert len(be.list_mappings()) == 1
    # Force session to look stale.
    s.last_activity = time.time() - 10
    expired = store.sweep_expired()
    assert s.id in expired
    removed = m.cleanup_session(s.id, reason="idle_timeout")
    assert removed == 1
    assert be.list_mappings() == []


def test_backend_failure_on_activate_surfaces(tmp_path, monkeypatch):
    be = MockIGD(secure_mode=True, local_ip="192.168.99.99")
    m, _ = _mgr(tmp_path, backend=be)
    m.start()
    with pytest.raises(MappingError, match="gateway rejected"):
        m.activate("s1", "alice", "rdp")  # secure_mode + different internal host
