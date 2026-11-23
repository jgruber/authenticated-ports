"""ForwardingBackend interface shared by the probe and the web app.

Any backend (UPnP today, a firewall backend tomorrow) exposes the same
surface so swapping is a one-line change in the web layer.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal

Protocol = Literal["tcp", "udp"]


class BackendError(RuntimeError):
    """Base exception for all backend failures."""


class DiscoveryError(BackendError):
    """Raised when the backend cannot find / reach the control endpoint."""


@dataclass(frozen=True)
class Mapping:
    external_port: int
    protocol: Protocol
    internal_host: str
    internal_port: int
    description: str = ""
    lease_seconds: int = 0  # 0 == indefinite from the device's perspective
    enabled: bool = True


def normalize_protocol(proto: str) -> Protocol:
    p = proto.strip().lower()
    if p not in ("tcp", "udp"):
        raise ValueError(f"protocol must be 'tcp' or 'udp', got {proto!r}")
    return p  # type: ignore[return-value]


class ForwardingBackend(ABC):
    """Pluggable port-forwarding backend.

    Implementations must be safe to construct without touching the network;
    network I/O happens in discover() and afterwards.
    """

    @abstractmethod
    def discover(self) -> dict:
        """Locate the control endpoint. Return a dict of diagnostics
        (at minimum: {"device": str, "control_url": str})."""

    @abstractmethod
    def get_external_ip(self) -> str:
        """Return the WAN-side IP seen by the gateway."""

    @abstractmethod
    def add_mapping(
        self,
        external_port: int,
        protocol: Protocol,
        internal_host: str,
        internal_port: int,
        lease_seconds: int,
        description: str,
    ) -> None:
        """Create a single port forward. Raise BackendError on failure."""

    @abstractmethod
    def remove_mapping(self, external_port: int, protocol: Protocol) -> None:
        """Delete a single port forward. Must be idempotent-friendly: raise
        BackendError only on unexpected failures, not on 'not present'."""

    @abstractmethod
    def list_mappings(self) -> list[Mapping]:
        """Return every mapping the device currently has (not just ours)."""

    def get_local_ip(self) -> str | None:
        """Best-effort: the local IP the backend presents to the gateway.
        Returning None is allowed. The probe uses this to pick a same-host
        internal address when the caller didn't supply one."""
        return None
