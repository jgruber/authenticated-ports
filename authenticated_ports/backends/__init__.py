"""Forwarding backends. The UPnP backend is the first implementation; a
firewall backend (nft/iptables/router API) can be dropped in later without
touching the web layer."""

from .base import (
    ForwardingBackend,
    BackendError,
    DiscoveryError,
    Mapping,
    Protocol,
)

__all__ = [
    "ForwardingBackend",
    "BackendError",
    "DiscoveryError",
    "Mapping",
    "Protocol",
]
