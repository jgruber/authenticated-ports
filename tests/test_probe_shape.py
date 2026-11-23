"""Smoke-tests for the probe's CLI surface — importable, parser works."""

from __future__ import annotations

from probe import upnp_probe


def test_parser_defaults():
    args = upnp_probe.build_parser().parse_args([])
    assert args.external_port == 51820
    assert args.internal_port == 51820
    assert args.lease == 120
    assert args.protocol == "tcp"
    assert args.cleanup is False


def test_lease_honored_judgment():
    f = upnp_probe._lease_judged_honored
    assert f(120, 120) is True
    assert f(118, 120) is True
    assert f(30, 120) is False
    assert f(0, 120) is False
    assert f(5, 0) is None
