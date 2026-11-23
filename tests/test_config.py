"""Config parsing and validation."""

from __future__ import annotations

import json

import pytest

from authenticated_ports.config import (
    AppConfig, ConfigError, load_mappings,
)


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj))
    return p


def test_valid_mappings(tmp_path):
    p = _write(tmp_path, "m.json", {"mappings": [
        {"id": "a", "name": "A", "protocol": "tcp",
         "external_port": 51000, "internal_host": "192.168.1.10",
         "internal_port": 22, "lease_seconds": 600},
        {"id": "b", "name": "B", "protocol": "udp",
         "external_port": 52000, "internal_host": "192.168.1.11",
         "internal_port": 27015},
    ]})
    cfg = load_mappings(p)
    assert len(cfg.mappings) == 2
    assert cfg.by_id("a").protocol == "tcp"
    assert cfg.by_id("b").lease_seconds == 3600  # default
    assert cfg.by_id("missing") is None


def test_duplicate_id_rejected(tmp_path):
    p = _write(tmp_path, "m.json", {"mappings": [
        {"id": "dup", "name": "A", "protocol": "tcp",
         "external_port": 51000, "internal_host": "1.2.3.4", "internal_port": 22},
        {"id": "dup", "name": "B", "protocol": "udp",
         "external_port": 52000, "internal_host": "1.2.3.4", "internal_port": 27015},
    ]})
    with pytest.raises(ConfigError, match="duplicate id"):
        load_mappings(p)


def test_duplicate_external_port_rejected(tmp_path):
    p = _write(tmp_path, "m.json", {"mappings": [
        {"id": "a", "name": "A", "protocol": "tcp",
         "external_port": 51000, "internal_host": "1.2.3.4", "internal_port": 22},
        {"id": "b", "name": "B", "protocol": "tcp",
         "external_port": 51000, "internal_host": "5.6.7.8", "internal_port": 80},
    ]})
    with pytest.raises(ConfigError, match="duplicate external_port"):
        load_mappings(p)


def test_same_external_port_different_proto_allowed(tmp_path):
    p = _write(tmp_path, "m.json", {"mappings": [
        {"id": "t", "name": "T", "protocol": "tcp",
         "external_port": 51000, "internal_host": "1.2.3.4", "internal_port": 22},
        {"id": "u", "name": "U", "protocol": "udp",
         "external_port": 51000, "internal_host": "1.2.3.4", "internal_port": 22},
    ]})
    cfg = load_mappings(p)
    assert len(cfg.mappings) == 2


def test_invalid_protocol_rejected(tmp_path):
    p = _write(tmp_path, "m.json", {"mappings": [
        {"id": "x", "name": "X", "protocol": "sctp",
         "external_port": 51000, "internal_host": "1.2.3.4", "internal_port": 22},
    ]})
    with pytest.raises((ConfigError, ValueError)):
        load_mappings(p)


def test_port_out_of_range_rejected(tmp_path):
    p = _write(tmp_path, "m.json", {"mappings": [
        {"id": "x", "name": "X", "protocol": "tcp",
         "external_port": 999999, "internal_host": "1.2.3.4", "internal_port": 22},
    ]})
    with pytest.raises(ConfigError, match="external_port"):
        load_mappings(p)


def test_missing_required_field(tmp_path):
    p = _write(tmp_path, "m.json", {"mappings": [
        {"id": "x", "protocol": "tcp",
         "external_port": 51000, "internal_host": "1.2.3.4", "internal_port": 22},
    ]})
    with pytest.raises(ConfigError, match="missing required field 'name'"):
        load_mappings(p)


def test_app_config_defaults_when_missing():
    cfg = AppConfig.load(None)
    assert cfg.idle_timeout_seconds == 1800
    assert cfg.lockout_threshold == 5


def test_app_config_rejects_unknown_key(tmp_path):
    p = _write(tmp_path, "c.json", {"not_a_key": 1})
    with pytest.raises(ConfigError, match="unknown key"):
        AppConfig.load(p)
