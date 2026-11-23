"""Backend-contract tests against a mock IGD — no real gateway required."""

from __future__ import annotations

import pytest

from authenticated_ports.backends import BackendError
from tests.mock_backend import MockIGD


def test_discover_and_external_ip():
    b = MockIGD()
    info = b.discover()
    assert info["device"] == "MockIGD"
    assert b.get_external_ip() == "203.0.113.5"


def test_add_list_remove_tcp_roundtrip():
    b = MockIGD()
    b.discover()
    b.add_mapping(51820, "tcp", "192.168.1.10", 22, 300, "test")
    [m] = b.list_mappings()
    assert m.external_port == 51820
    assert m.protocol == "tcp"
    assert m.internal_host == "192.168.1.10"
    assert m.internal_port == 22
    assert m.lease_seconds == 300
    b.remove_mapping(51820, "tcp")
    assert b.list_mappings() == []


def test_udp_is_supported():
    b = MockIGD()
    b.discover()
    b.add_mapping(55555, "udp", "192.168.1.10", 27015, 60, "udp")
    assert any(m.protocol == "udp" for m in b.list_mappings())


def test_remove_missing_is_quiet():
    b = MockIGD()
    b.discover()
    b.remove_mapping(9999, "tcp")  # must not raise


def test_secure_mode_blocks_diff_host_but_allows_same_host():
    b = MockIGD(local_ip="192.168.1.10", secure_mode=True)
    b.discover()
    b.add_mapping(51820, "tcp", "192.168.1.10", 22, 60, "self")  # ok
    with pytest.raises(BackendError):
        b.add_mapping(51821, "tcp", "192.168.1.99", 22, 60, "other")


def test_invalid_protocol_rejected():
    b = MockIGD()
    b.discover()
    with pytest.raises(ValueError):
        b.add_mapping(10000, "sctp", "192.168.1.10", 10000, 60, "bad")  # type: ignore[arg-type]


def test_operations_before_discover_raise():
    b = MockIGD()
    with pytest.raises(BackendError):
        b.get_external_ip()
