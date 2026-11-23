#!/usr/bin/env python3
"""UPnP IGD probe / sanity tester for the authenticated-ports project.

Goals:
  * Prove the gateway speaks UPnP and will accept AddPortMapping from this
    host.
  * Detect whether miniupnpd "secure mode" is restricting mappings to the
    requesting host (same-IP) only.
  * Never leave test mappings behind.

Example:
    python3 probe/upnp_probe.py \\
        --external-port 51820 \\
        --internal-host 192.168.1.50 \\
        --internal-port 51820 \\
        --protocol tcp \\
        --lease 120
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

# Allow `python3 probe/upnp_probe.py` without installing the package.
_HERE = os.path.abspath(os.path.dirname(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, os.pardir))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from authenticated_ports.backends import BackendError, DiscoveryError, Mapping  # noqa: E402
from authenticated_ports.backends.upnp import UpnpBackend  # noqa: E402

PROBE_DESC = "authenticated-ports-probe"


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str = ""
    skipped: bool = False

    @property
    def status(self) -> str:
        if self.skipped:
            return "SKIP"
        return "PASS" if self.passed else "FAIL"


@dataclass
class ProbeReport:
    checks: list[CheckResult] = field(default_factory=list)
    device: str = ""
    control_url: str = ""
    external_ip: str = ""
    local_ip: str = ""
    impl: str = ""
    secure_mode_detected: bool = False
    lease_honored: Optional[bool] = None

    def add(self, c: CheckResult) -> None:
        self.checks.append(c)

    def failed_critical(self, critical_names: set[str]) -> bool:
        return any(
            (not c.passed) and (not c.skipped) and c.name in critical_names
            for c in self.checks
        )


def _print_banner(title: str) -> None:
    print()
    print(f"=== {title} ===")


def _print_table(report: ProbeReport) -> None:
    _print_banner("Results")
    width = max((len(c.name) for c in report.checks), default=10)
    for c in report.checks:
        detail = f"  {c.detail}" if c.detail else ""
        print(f"  [{c.status:4}] {c.name:<{width}}{detail}")


# --- helpers --------------------------------------------------------------

def _wait_present(
    backend: UpnpBackend, ext_port: int, proto: str, timeout: float = 3.0
) -> Optional[Mapping]:
    """Poll list_mappings() until the given (ext_port, proto) shows up."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            for m in backend.list_mappings():
                if m.external_port == ext_port and m.protocol.lower() == proto.lower():
                    return m
        except BackendError:
            pass
        time.sleep(0.25)
    return None


def _wait_gone(
    backend: UpnpBackend, ext_port: int, proto: str, timeout: float = 3.0
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            still = any(
                m.external_port == ext_port and m.protocol.lower() == proto.lower()
                for m in backend.list_mappings()
            )
        except BackendError:
            still = True
        if not still:
            return True
        time.sleep(0.25)
    return False


def _try_add_delete(
    backend: UpnpBackend,
    ext_port: int,
    proto: str,
    internal_host: str,
    internal_port: int,
    lease: int,
    description: str,
) -> tuple[bool, str, Optional[Mapping]]:
    """Attempt add + list + delete. Returns (ok, detail, observed_mapping)."""
    try:
        backend.add_mapping(ext_port, proto, internal_host, internal_port, lease, description)
    except BackendError as e:
        return (False, f"add failed: {e}", None)

    observed = _wait_present(backend, ext_port, proto, timeout=3.0)
    if observed is None:
        # try delete anyway so we don't leak
        try:
            backend.remove_mapping(ext_port, proto)
        except BackendError:
            pass
        return (False, "added but did not appear in list", None)

    try:
        backend.remove_mapping(ext_port, proto)
    except BackendError as e:
        return (False, f"delete failed: {e}", observed)

    if not _wait_gone(backend, ext_port, proto, timeout=3.0):
        return (False, "delete returned ok but mapping still present", observed)

    return (True, "ok", observed)


def _cleanup_probe_mappings(backend: UpnpBackend, description_tag: str) -> int:
    """Delete any mapping whose description contains our probe tag."""
    try:
        mappings = backend.list_mappings()
    except BackendError as e:
        print(f"  cleanup: list failed: {e}", file=sys.stderr)
        return 0
    removed = 0
    for m in mappings:
        if description_tag in (m.description or ""):
            try:
                backend.remove_mapping(m.external_port, m.protocol)
                removed += 1
                print(f"  cleanup: removed {m.protocol.upper()}/{m.external_port} "
                      f"-> {m.internal_host}:{m.internal_port} "
                      f"({m.description!r})")
            except BackendError as e:
                print(f"  cleanup: failed to remove {m.protocol}/{m.external_port}: {e}",
                      file=sys.stderr)
    return removed


# --- main probe flow ------------------------------------------------------

def run_probe(args: argparse.Namespace) -> ProbeReport:
    report = ProbeReport()
    backend = UpnpBackend(prefer=args.prefer)

    # 1. discovery
    _print_banner("Discovery")
    try:
        info = backend.discover()
    except DiscoveryError as e:
        report.add(CheckResult("discovery", False, str(e)))
        return report
    report.device = info.get("device", "")
    report.control_url = info.get("control_url", "")
    report.local_ip = info.get("lan_ip") or ""
    report.impl = info.get("impl", "")
    print(f"  impl:        {report.impl}")
    print(f"  device:      {report.device or '(unknown)'}")
    print(f"  controlURL:  {report.control_url}")
    print(f"  local IP:    {report.local_ip or '(unknown)'}")
    report.add(CheckResult("discovery", True, f"via {report.impl}"))

    # 2. external IP
    _print_banner("External IP")
    try:
        ext_ip = backend.get_external_ip()
        report.external_ip = ext_ip
        print(f"  external IP: {ext_ip}")
        report.add(CheckResult("external_ip", True, ext_ip))
    except BackendError as e:
        report.add(CheckResult("external_ip", False, str(e)))

    # Opportunistic early cleanup of any stale probe entries from an aborted run.
    _print_banner("Pre-run cleanup of stale probe entries")
    stale = _cleanup_probe_mappings(backend, PROBE_DESC)
    print(f"  removed {stale} stale probe mapping(s)")

    # 3. same-host TCP
    local_ip = report.local_ip or backend.get_local_ip() or ""
    if not local_ip:
        report.add(CheckResult(
            "same_host_tcp", False, "no local IP detected; cannot run same-host test"
        ))
    else:
        _print_banner(f"Same-host TCP (internal = this host, {local_ip})")
        ok, detail, observed = _try_add_delete(
            backend,
            args.external_port,
            "tcp",
            local_ip,
            args.internal_port,
            args.lease,
            f"{PROBE_DESC} same-host tcp",
        )
        report.add(CheckResult("same_host_tcp", ok, detail))
        if observed is not None:
            report.lease_honored = _lease_judged_honored(observed.lease_seconds, args.lease)

    # 4. different-host TCP (the secure_mode test)
    if args.internal_host:
        _print_banner(f"Different-host TCP (internal = {args.internal_host})")
        ok, detail, _ = _try_add_delete(
            backend,
            args.external_port + 1,  # offset so we don't collide with same-host test
            "tcp",
            args.internal_host,
            args.internal_port,
            args.lease,
            f"{PROBE_DESC} diff-host tcp",
        )
        report.add(CheckResult("diff_host_tcp", ok, detail))
        same_host_passed = any(
            c.name == "same_host_tcp" and c.passed for c in report.checks
        )
        if same_host_passed and not ok:
            report.secure_mode_detected = True
    else:
        report.add(CheckResult(
            "diff_host_tcp", False,
            "skipped: pass --internal-host to run the secure_mode check",
            skipped=True,
        ))

    # 5. UDP mapping (same-host, because secure_mode may block diff-host)
    if local_ip:
        _print_banner(f"UDP mapping (same-host, {local_ip})")
        ok, detail, _ = _try_add_delete(
            backend,
            args.external_port + 2,
            "udp",
            local_ip,
            args.internal_port,
            args.lease,
            f"{PROBE_DESC} same-host udp",
        )
        report.add(CheckResult("udp_mapping", ok, detail))
    else:
        report.add(CheckResult("udp_mapping", False, "no local IP", skipped=True))

    # 6. Lease honored?
    if report.lease_honored is True:
        report.add(CheckResult("lease_honored", True, f"requested {args.lease}s"))
    elif report.lease_honored is False:
        report.add(CheckResult(
            "lease_honored", False,
            f"requested {args.lease}s but device reported a different value",
        ))
    else:
        report.add(CheckResult(
            "lease_honored", False, "no observation captured", skipped=True
        ))

    # 7. Final safety sweep
    _print_banner("Final cleanup")
    left = _cleanup_probe_mappings(backend, PROBE_DESC)
    print(f"  removed {left} probe mapping(s)")

    return report


def _lease_judged_honored(reported: int, requested: int) -> Optional[bool]:
    if requested <= 0:
        return None
    if reported <= 0:
        return False
    # miniupnpd typically decrements by the time between add and list; give slack.
    return abs(reported - requested) <= max(5, requested // 10)


def _print_interpretation(report: ProbeReport) -> None:
    _print_banner("Interpretation")
    if not any(c.name == "discovery" and c.passed for c in report.checks):
        print("  No UPnP IGD could be discovered. Confirm the gateway has UPnP enabled")
        print("  and that you are running the probe on the SAME LAN as the gateway.")
        return

    same = next((c for c in report.checks if c.name == "same_host_tcp"), None)
    diff = next((c for c in report.checks if c.name == "diff_host_tcp"), None)

    if report.secure_mode_detected:
        print("  Gateway appears to enforce UPnP secure mode:")
        print("  mappings can only target the requesting host.")
        print("  Workarounds:")
        print("    * Run the authenticated-ports app on the host you want to expose.")
        print("    * Disable secure_mode on miniupnpd (if the gateway allows it).")
        print("    * Use a firewall backend (nft/iptables/router API) instead of UPnP.")
    elif same and same.passed and diff and diff.passed:
        print("  Gateway accepts mappings to arbitrary internal hosts.")
        print("  The authenticated-ports web app can run on any LAN host and forward")
        print("  to any other internal host/port defined in mappings.json.")
    elif same and same.passed and diff and diff.skipped:
        print("  Same-host mappings work; different-host was skipped (no --internal-host).")
        print("  Re-run with --internal-host <some-other-LAN-IP> to detect secure_mode.")
    else:
        print("  Mixed / failing results — review the table above.")

    lh = next((c for c in report.checks if c.name == "lease_honored"), None)
    if lh and not lh.passed and not lh.skipped:
        print("  Note: the gateway may be ignoring or clamping the requested lease.")
        print("  The app will still work but auto-expiry will not line up with the config value.")


# --- argparse -------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="upnp_probe",
        description="Probe a UPnP IGD for the authenticated-ports project.",
    )
    p.add_argument("--external-port", type=int, default=51820,
                   help="base external port to use for test mappings (default: 51820). "
                        "The probe uses this, +1 for diff-host, +2 for UDP.")
    p.add_argument("--internal-host",
                   help="LAN IP of another host for the secure_mode check.")
    p.add_argument("--internal-port", type=int, default=51820,
                   help="internal port to target (default: 51820).")
    p.add_argument("--protocol", choices=("tcp", "udp"), default="tcp",
                   help="protocol context label (same-host and UDP tests run both).")
    p.add_argument("--lease", type=int, default=120,
                   help="lease duration in seconds (default: 120).")
    p.add_argument("--cleanup", action="store_true",
                   help="only delete any leftover mappings tagged with the probe "
                        "description, then exit.")
    p.add_argument("--prefer", choices=("auto", "library", "cli"), default="auto",
                   help="force the miniupnpc backend implementation.")
    p.add_argument("--json", action="store_true",
                   help="also print a JSON summary at the end.")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.cleanup:
        backend = UpnpBackend(prefer=args.prefer)
        try:
            info = backend.discover()
        except DiscoveryError as e:
            print(f"discovery failed: {e}", file=sys.stderr)
            return 2
        print(f"Cleaning up probe mappings on {info.get('device') or 'IGD'} ...")
        n = _cleanup_probe_mappings(backend, PROBE_DESC)
        print(f"removed {n} mapping(s)")
        return 0

    report = run_probe(args)
    _print_table(report)
    _print_interpretation(report)

    if args.json:
        import json
        _print_banner("JSON summary")
        print(json.dumps({
            "device": report.device,
            "control_url": report.control_url,
            "external_ip": report.external_ip,
            "local_ip": report.local_ip,
            "impl": report.impl,
            "secure_mode_detected": report.secure_mode_detected,
            "checks": [
                {"name": c.name, "status": c.status, "detail": c.detail}
                for c in report.checks
            ],
        }, indent=2))

    critical = {"discovery", "external_ip", "same_host_tcp"}
    return 1 if report.failed_critical(critical) else 0


if __name__ == "__main__":
    raise SystemExit(main())
