"""Config loaders for mappings.json and the app config.

credentials.json is handled separately in auth.py because it's touched
every login (and by the useradd CLI).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .backends.base import Protocol, normalize_protocol

_ID_MIN, _ID_MAX = 1, 64
_PORT_MIN, _PORT_MAX = 1, 65535
_LEASE_MIN, _LEASE_MAX = 30, 24 * 60 * 60  # 30s..24h


class ConfigError(ValueError):
    """Raised for any config-file problem."""


@dataclass(frozen=True)
class AllowedMapping:
    id: str
    name: str
    protocol: Protocol
    external_port: int
    internal_host: str
    internal_port: int
    lease_seconds: int
    description: str = ""


@dataclass
class AppConfig:
    listen_host: str = "0.0.0.0"
    listen_port: int = 8443
    tls_cert: str | None = None
    tls_key: str | None = None
    idle_timeout_seconds: int = 30 * 60
    lockout_threshold: int = 5
    lockout_window_seconds: int = 15 * 60
    secret_key: str | None = None  # signing key for cookies; if None, generated at boot
    credentials_path: str = "credentials.json"
    mappings_path: str = "mappings.json"
    state_path: str = "state/active_mappings.json"
    audit_log_path: str = "state/audit.log"
    description_prefix: str = "authenticated-ports"
    behind_proxy: bool = False  # trust X-Forwarded-For/-Proto/-Host
    cookie_secure: bool = True  # set Secure flag on cookies
    trusted_proxy_hops: int = 1  # how many proxy hops to trust when behind_proxy

    @staticmethod
    def load(path: str | os.PathLike[str] | None) -> "AppConfig":
        cfg = AppConfig()
        if not path:
            return cfg
        p = Path(path)
        if not p.exists():
            return cfg
        try:
            data = json.loads(p.read_text())
        except json.JSONDecodeError as e:
            raise ConfigError(f"{p}: invalid JSON: {e}") from e
        if not isinstance(data, dict):
            raise ConfigError(f"{p}: top level must be an object")
        for k, v in data.items():
            if not hasattr(cfg, k):
                raise ConfigError(f"{p}: unknown key {k!r}")
            setattr(cfg, k, v)
        if cfg.idle_timeout_seconds < 60:
            raise ConfigError("idle_timeout_seconds must be >= 60")
        if cfg.lockout_threshold < 1:
            raise ConfigError("lockout_threshold must be >= 1")
        return cfg


def _require(obj: dict, key: str, kind: type, where: str) -> object:
    if key not in obj:
        raise ConfigError(f"{where}: missing required field {key!r}")
    v = obj[key]
    if not isinstance(v, kind):
        raise ConfigError(f"{where}: field {key!r} must be {kind.__name__}, got {type(v).__name__}")
    return v


def _check_port(n: int, where: str, field_: str) -> int:
    if not isinstance(n, int) or isinstance(n, bool):
        raise ConfigError(f"{where}: {field_} must be an integer")
    if not (_PORT_MIN <= n <= _PORT_MAX):
        raise ConfigError(f"{where}: {field_} {n} out of range {_PORT_MIN}-{_PORT_MAX}")
    return n


def _check_id(s: str, where: str) -> str:
    if not (_ID_MIN <= len(s) <= _ID_MAX):
        raise ConfigError(f"{where}: id must be {_ID_MIN}..{_ID_MAX} chars")
    if not all(c.isalnum() or c in "-_" for c in s):
        raise ConfigError(f"{where}: id must be alphanumeric with '-' or '_'")
    return s


def _check_host(s: str, where: str) -> str:
    # We don't force IPv4-only, but we do forbid obviously-dangerous values.
    s = s.strip()
    if not s:
        raise ConfigError(f"{where}: internal_host must be non-empty")
    if any(c.isspace() for c in s):
        raise ConfigError(f"{where}: internal_host contains whitespace")
    return s


def parse_allowed_mapping(obj: dict, index: int) -> AllowedMapping:
    where = f"mappings[{index}]"
    if not isinstance(obj, dict):
        raise ConfigError(f"{where}: must be an object")
    raw_id = _require(obj, "id", str, where)
    _check_id(raw_id, where)
    name = _require(obj, "name", str, where).strip() or raw_id
    proto = normalize_protocol(_require(obj, "protocol", str, where))
    ext = _check_port(_require(obj, "external_port", int, where), where, "external_port")
    host = _check_host(_require(obj, "internal_host", str, where), where)
    internal = _check_port(_require(obj, "internal_port", int, where), where, "internal_port")
    lease = int(obj.get("lease_seconds", 3600))
    if not (_LEASE_MIN <= lease <= _LEASE_MAX):
        raise ConfigError(
            f"{where}: lease_seconds {lease} out of range {_LEASE_MIN}-{_LEASE_MAX}"
        )
    description = str(obj.get("description", "")).strip()
    return AllowedMapping(
        id=raw_id, name=name, protocol=proto,
        external_port=ext, internal_host=host, internal_port=internal,
        lease_seconds=lease, description=description,
    )


@dataclass
class MappingsConfig:
    mappings: list[AllowedMapping] = field(default_factory=list)

    def by_id(self, mapping_id: str) -> AllowedMapping | None:
        for m in self.mappings:
            if m.id == mapping_id:
                return m
        return None


def load_mappings(path: str | os.PathLike[str]) -> MappingsConfig:
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"mappings file {p} does not exist")
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        raise ConfigError(f"{p}: invalid JSON: {e}") from e
    if not isinstance(data, dict) or "mappings" not in data:
        raise ConfigError(f"{p}: top-level object must have a 'mappings' array")
    raw = data["mappings"]
    if not isinstance(raw, list):
        raise ConfigError(f"{p}: 'mappings' must be a list")
    parsed: list[AllowedMapping] = []
    seen_ids: set[str] = set()
    seen_ext: set[tuple[int, str]] = set()
    for i, obj in enumerate(raw):
        m = parse_allowed_mapping(obj, i)
        if m.id in seen_ids:
            raise ConfigError(f"mappings[{i}]: duplicate id {m.id!r}")
        key = (m.external_port, m.protocol)
        if key in seen_ext:
            raise ConfigError(
                f"mappings[{i}]: duplicate external_port/protocol "
                f"{m.external_port}/{m.protocol}"
            )
        seen_ids.add(m.id)
        seen_ext.add(key)
        parsed.append(m)
    return MappingsConfig(mappings=parsed)
