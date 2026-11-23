"""UPnP IGD backend.

Prefers the `miniupnpc` Python library when importable; otherwise shells
out to the `upnpc` CLI from the miniupnpc package. The two implementations
present the same ForwardingBackend surface.
"""

from __future__ import annotations

import logging
import re
import shutil
import socket
import subprocess
from typing import Optional

from .base import (
    BackendError,
    DiscoveryError,
    ForwardingBackend,
    Mapping,
    Protocol,
    normalize_protocol,
)

log = logging.getLogger(__name__)

try:  # library path
    import miniupnpc  # type: ignore

    _HAS_LIB = True
except Exception:  # pragma: no cover - import probe
    _HAS_LIB = False


def _best_local_ip() -> Optional[str]:
    """Pick the local IP that would be used to reach the LAN default
    gateway. No packets are actually sent."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.168.1.1", 1))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


class _LibUpnpBackend(ForwardingBackend):
    """miniupnpc-library implementation."""

    def __init__(self, discover_delay_ms: int = 2000) -> None:
        self._discover_delay_ms = discover_delay_ms
        self._u: Optional["miniupnpc.UPnP"] = None  # type: ignore[name-defined]
        self._device: str = ""
        self._control_url: str = ""
        self._local_ip: Optional[str] = None

    def discover(self) -> dict:
        u = miniupnpc.UPnP()
        u.discoverdelay = self._discover_delay_ms
        n = u.discover()
        if not n:
            raise DiscoveryError("no UPnP IGD devices responded to SSDP")
        try:
            u.selectigd()
        except Exception as e:
            raise DiscoveryError(f"selectigd failed: {e}") from e
        self._u = u
        self._control_url = getattr(u, "controlURL", "") or ""
        # friendly name / model varies by firmware; keep it best-effort
        self._device = getattr(u, "friendlyname", "") or getattr(u, "statusinfo", lambda: ("",))()[0] or "UPnP IGD"
        self._local_ip = getattr(u, "lanaddr", None) or _best_local_ip()
        return {
            "device": self._device,
            "control_url": self._control_url,
            "lan_ip": self._local_ip,
            "num_devices_found": n,
            "impl": "miniupnpc-library",
        }

    def _require(self) -> "miniupnpc.UPnP":  # type: ignore[name-defined]
        if self._u is None:
            raise BackendError("discover() has not been called")
        return self._u

    def get_external_ip(self) -> str:
        u = self._require()
        ip = u.externalipaddress()
        if not ip:
            raise BackendError("gateway returned no external IP")
        return ip

    def add_mapping(
        self,
        external_port: int,
        protocol: Protocol,
        internal_host: str,
        internal_port: int,
        lease_seconds: int,
        description: str,
    ) -> None:
        u = self._require()
        proto = normalize_protocol(protocol).upper()
        try:
            ok = u.addportmapping(
                external_port,
                proto,
                internal_host,
                internal_port,
                description or "",
                "",  # remote host — empty == any
                lease_seconds,
            )
        except Exception as e:
            raise BackendError(f"AddPortMapping failed: {e}") from e
        if not ok:
            raise BackendError("AddPortMapping returned False")

    def remove_mapping(self, external_port: int, protocol: Protocol) -> None:
        u = self._require()
        proto = normalize_protocol(protocol).upper()
        try:
            u.deleteportmapping(external_port, proto)
        except Exception as e:
            # miniupnpc raises on NoSuchEntryInArray (714). Treat as not-present.
            msg = str(e)
            if "714" in msg or "NoSuchEntry" in msg:
                return
            raise BackendError(f"DeletePortMapping failed: {e}") from e

    def list_mappings(self) -> list[Mapping]:
        u = self._require()
        out: list[Mapping] = []
        i = 0
        while True:
            try:
                p = u.getgenericportmapping(i)
            except Exception:
                break
            if p is None:
                break
            # miniupnpc returns:
            # (ext_port, proto, (int_host, int_port), description, enabled, remote_host, lease)
            try:
                ext_port, proto, (int_host, int_port), desc, enabled, _remote, lease = p
            except (ValueError, TypeError):
                # some bindings return 7 flat elements
                try:
                    ext_port, proto, int_host, int_port, desc, enabled, lease = p  # type: ignore[misc]
                except Exception:
                    break
            out.append(
                Mapping(
                    external_port=int(ext_port),
                    protocol=normalize_protocol(str(proto)),
                    internal_host=str(int_host),
                    internal_port=int(int_port),
                    description=str(desc or ""),
                    lease_seconds=int(lease or 0),
                    enabled=bool(enabled),
                )
            )
            i += 1
            if i > 4096:  # paranoia
                break
        return out

    def get_local_ip(self) -> Optional[str]:
        return self._local_ip


_UPNPC_LIST_RE = re.compile(
    r"""^\s*\d+\s+(?P<proto>TCP|UDP)\s+
        (?P<ext>\d+)\s*->\s*
        (?P<host>[\d.]+):(?P<int>\d+)
        \s+'(?P<desc>[^']*)'
        \s+'(?P<remote>[^']*)'
        \s*(?P<lease>\d+)?""",
    re.X | re.I,
)


class _CliUpnpBackend(ForwardingBackend):
    """Shell-out fallback using the `upnpc` CLI from miniupnpc."""

    def __init__(self, upnpc_path: Optional[str] = None) -> None:
        self._upnpc = upnpc_path or shutil.which("upnpc") or shutil.which("upnpc-static")
        if not self._upnpc:
            raise DiscoveryError(
                "neither the miniupnpc Python library nor the `upnpc` CLI is available"
            )
        self._external_ip: Optional[str] = None
        self._control_url: Optional[str] = None
        self._device: str = "UPnP IGD"
        self._local_ip: Optional[str] = None

    def _run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        cmd = [self._upnpc, *args]
        log.debug("exec %s", cmd)
        return subprocess.run(
            cmd, capture_output=True, text=True, check=check, timeout=30
        )

    def discover(self) -> dict:
        try:
            r = self._run("-s")
        except FileNotFoundError as e:
            raise DiscoveryError(str(e)) from e
        except subprocess.CalledProcessError as e:
            raise DiscoveryError(f"upnpc -s failed: {e.stderr or e.stdout}") from e
        out = r.stdout
        m = re.search(r"Found valid IGD\s*:\s*(\S+)", out)
        if m:
            self._control_url = m.group(1)
        m = re.search(r"ExternalIPAddress\s*=\s*([\d.]+)", out)
        if m:
            self._external_ip = m.group(1)
        m = re.search(r"Local LAN ip address\s*:\s*([\d.]+)", out)
        if m:
            self._local_ip = m.group(1)
        else:
            self._local_ip = _best_local_ip()
        if not self._control_url:
            raise DiscoveryError("upnpc did not report a valid IGD")
        # try to grab a friendly name from -st output (not all firmwares print one)
        try:
            st = self._run("-st", check=False).stdout
            m = re.search(r"friendlyName\s*:\s*(.+)", st)
            if m:
                self._device = m.group(1).strip()
        except Exception:
            pass
        return {
            "device": self._device,
            "control_url": self._control_url,
            "lan_ip": self._local_ip,
            "external_ip_from_discover": self._external_ip,
            "impl": "upnpc-cli",
        }

    def get_external_ip(self) -> str:
        if self._external_ip:
            return self._external_ip
        r = self._run("-s")
        m = re.search(r"ExternalIPAddress\s*=\s*([\d.]+)", r.stdout)
        if not m:
            raise BackendError("could not parse ExternalIPAddress from upnpc output")
        self._external_ip = m.group(1)
        return self._external_ip

    def add_mapping(
        self,
        external_port: int,
        protocol: Protocol,
        internal_host: str,
        internal_port: int,
        lease_seconds: int,
        description: str,
    ) -> None:
        proto = normalize_protocol(protocol).upper()
        # upnpc -e "desc" -a <internal_host> <int_port> <ext_port> <proto> [lease]
        args = ["-e", description or "authenticated-ports",
                "-a", internal_host, str(internal_port),
                str(external_port), proto]
        if lease_seconds and lease_seconds > 0:
            args.append(str(lease_seconds))
        try:
            r = self._run(*args)
        except subprocess.CalledProcessError as e:
            raise BackendError(f"upnpc -a failed: {(e.stderr or e.stdout).strip()}") from e
        if "is redirected to internal" not in r.stdout and "AddPortMapping" not in r.stdout:
            # some builds print different confirmations; fall through unless there's a visible failure
            if "failed with code" in r.stdout.lower() or "error" in r.stdout.lower():
                raise BackendError(f"upnpc -a reported failure: {r.stdout.strip()}")

    def remove_mapping(self, external_port: int, protocol: Protocol) -> None:
        proto = normalize_protocol(protocol).upper()
        try:
            r = self._run("-d", str(external_port), proto, check=False)
        except subprocess.CalledProcessError as e:  # pragma: no cover - check=False
            raise BackendError(str(e)) from e
        txt = (r.stdout + r.stderr).lower()
        if "no such entry" in txt or "714" in txt:
            return
        if r.returncode != 0 and "error" in txt:
            raise BackendError(f"upnpc -d failed: {r.stdout.strip()}")

    def list_mappings(self) -> list[Mapping]:
        try:
            r = self._run("-l")
        except subprocess.CalledProcessError as e:
            raise BackendError(f"upnpc -l failed: {e.stderr or e.stdout}") from e
        out: list[Mapping] = []
        for line in r.stdout.splitlines():
            m = _UPNPC_LIST_RE.match(line)
            if not m:
                continue
            out.append(
                Mapping(
                    external_port=int(m.group("ext")),
                    protocol=normalize_protocol(m.group("proto")),
                    internal_host=m.group("host"),
                    internal_port=int(m.group("int")),
                    description=m.group("desc") or "",
                    lease_seconds=int(m.group("lease") or 0),
                    enabled=True,
                )
            )
        return out

    def get_local_ip(self) -> Optional[str]:
        return self._local_ip


class UpnpBackend(ForwardingBackend):
    """Public UPnP backend. Delegates to the library impl when available,
    falls back to the upnpc CLI otherwise."""

    def __init__(self, prefer: str = "auto") -> None:
        """prefer: 'auto' | 'library' | 'cli'."""
        self._prefer = prefer
        self._impl: Optional[ForwardingBackend] = None

    def _select(self) -> ForwardingBackend:
        if self._impl is not None:
            return self._impl
        if self._prefer == "library":
            if not _HAS_LIB:
                raise DiscoveryError("miniupnpc library requested but not importable")
            self._impl = _LibUpnpBackend()
        elif self._prefer == "cli":
            self._impl = _CliUpnpBackend()
        else:  # auto
            self._impl = _LibUpnpBackend() if _HAS_LIB else _CliUpnpBackend()
        return self._impl

    def discover(self) -> dict:
        return self._select().discover()

    def get_external_ip(self) -> str:
        return self._select().get_external_ip()

    def add_mapping(
        self,
        external_port: int,
        protocol: Protocol,
        internal_host: str,
        internal_port: int,
        lease_seconds: int,
        description: str,
    ) -> None:
        self._select().add_mapping(
            external_port, protocol, internal_host, internal_port, lease_seconds, description
        )

    def remove_mapping(self, external_port: int, protocol: Protocol) -> None:
        self._select().remove_mapping(external_port, protocol)

    def list_mappings(self) -> list[Mapping]:
        return self._select().list_mappings()

    def get_local_ip(self) -> Optional[str]:
        return self._select().get_local_ip()
