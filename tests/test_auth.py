"""AuthService: hashing, verification, lockout."""

from __future__ import annotations

import json
import time

import pytest

from authenticated_ports.auth import AuthService


def _write_creds(tmp_path, users):
    p = tmp_path / "creds.json"
    p.write_text(json.dumps({"users": users}))
    return p


def test_set_user_creates_argon2id_hash(tmp_path):
    p = tmp_path / "creds.json"
    a = AuthService(p)
    created = a.set_user("alice", "hunter22!")
    assert created is True
    data = json.loads(p.read_text())
    [u] = data["users"]
    assert u["username"] == "alice"
    assert u["password_hash"].startswith("$argon2id$")
    # file permissions are 0600
    assert (p.stat().st_mode & 0o777) == 0o600


def test_verify_round_trip(tmp_path):
    a = AuthService(tmp_path / "creds.json")
    a.set_user("bob", "s3cret-pw-forreal")
    r = a.verify("bob", "s3cret-pw-forreal")
    assert r.ok
    assert r.user["username"] == "bob"
    r = a.verify("bob", "wrong")
    assert not r.ok
    assert r.failure == "bad_password"


def test_unknown_user_returns_specific_failure(tmp_path):
    a = AuthService(tmp_path / "creds.json")
    r = a.verify("noone", "whatever")
    assert not r.ok
    assert r.failure == "unknown_user"


def test_lockout_after_threshold(tmp_path):
    a = AuthService(tmp_path / "creds.json",
                    lockout_threshold=3, lockout_window_seconds=60)
    a.set_user("carol", "p@ssword12")
    for _ in range(3):
        r = a.verify("carol", "nope")
        assert not r.ok
    # Now locked out even with correct password.
    r = a.verify("carol", "p@ssword12")
    assert not r.ok
    assert r.failure == "locked_out"


def test_successful_login_clears_failure_count(tmp_path):
    a = AuthService(tmp_path / "creds.json",
                    lockout_threshold=5, lockout_window_seconds=60)
    a.set_user("dave", "goodpass12")
    a.verify("dave", "x")
    a.verify("dave", "y")
    assert a.failure_count("dave") == 2
    r = a.verify("dave", "goodpass12")
    assert r.ok
    assert a.failure_count("dave") == 0


def test_delete_user(tmp_path):
    a = AuthService(tmp_path / "creds.json")
    a.set_user("eve", "throwaway1")
    assert a.delete_user("eve") is True
    assert a.delete_user("eve") is False
    assert a.list_users() == []


def test_set_user_rejects_whitespace_username(tmp_path):
    a = AuthService(tmp_path / "creds.json")
    with pytest.raises(ValueError):
        a.set_user("foo bar", "goodpass")
    with pytest.raises(ValueError):
        a.set_user("", "goodpass")


def test_corrupt_hash_scheme_surfaces(tmp_path):
    p = _write_creds(tmp_path, [{"username": "x", "password_hash": "plaintext!!"}])
    a = AuthService(p)
    r = a.verify("x", "whatever")
    assert not r.ok
    assert r.failure == "bad_hash"
