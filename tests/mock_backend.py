"""In-memory ForwardingBackend used by tests (and by the probe in --dry-run
sense if ever useful). Simulates optional secure_mode and a honored lease."""

from __future__ import annotations

from typing import Optional

from authenticated_ports.backends import (
    BackendError,
    DiscoveryError,
    ForwardingBackend,
    Mapping,
    Protocol,
)
from authenticated_ports.backends.base import normalize_protocol


class MockIGD(ForwardingBackend):
    def __init__(
        self,
        local_ip: str = "192.168.1.10",
        external_ip: str = "203.0.113.5",
        secure_mode: bool = False,
        device: str = "MockIGD",
        fail_discovery: bool = False,
    ) -> None:
        self._local_ip = local_ip
        self._external_ip = external_ip
        self._secure_mode = secure_mode
        self._device = device
        self._fail_discovery = fail_discovery
        self._discovered = False
        self._mappings: dict[tuple[int, Protocol], Mapping] = {}

    def discover(self) -> dict:
        if self._fail_discovery:
            raise DiscoveryError("mock: no IGD")
        self._discovered = True
        return {
            "device": self._device,
            "control_url": "http://mock/ctl",
            "lan_ip": self._local_ip,
            "impl": "mock",
        }

    def _require(self) -> None:
        if not self._discovered:
            raise BackendError("discover() has not been called")

    def get_external_ip(self) -> str:
        self._require()
        return self._external_ip

    def add_mapping(self, external_port, protocol, internal_host, internal_port,
                    lease_seconds, description):
        self._require()
        proto = normalize_protocol(protocol)
        if self._secure_mode and internal_host != self._local_ip:
            raise BackendError("mock: secure_mode blocks mapping to other hosts")
        key = (external_port, proto)
        self._mappings[key] = Mapping(
            external_port=external_port,
            protocol=proto,
            internal_host=internal_host,
            internal_port=internal_port,
            description=description or "",
            lease_seconds=lease_seconds,
            enabled=True,
        )

    def remove_mapping(self, external_port, protocol):
        self._require()
        proto = normalize_protocol(protocol)
        self._mappings.pop((external_port, proto), None)

    def list_mappings(self) -> list[Mapping]:
        self._require()
        return list(self._mappings.values())

    def get_local_ip(self) -> Optional[str]:
        return self._local_ip
