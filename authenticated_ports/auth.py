"""Credential verification + per-user lockout.

Passwords are hashed with argon2id. Existing bcrypt hashes in credentials.json
are honored *only* when the `bcrypt` package is importable; new hashes
written by the `useradd` CLI are always argon2id.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

try:
    import bcrypt as _bcrypt  # optional
    _HAS_BCRYPT = True
except Exception:  # pragma: no cover
    _HAS_BCRYPT = False


LoginFailure = Literal[
    "unknown_user", "bad_password", "locked_out", "bad_hash",
]


@dataclass
class VerifyResult:
    ok: bool
    user: dict | None = None  # the full user record on success
    failure: LoginFailure | None = None


@dataclass
class _Attempts:
    failures: list[float] = field(default_factory=list)
    locked_until: float = 0.0


class AuthService:
    def __init__(
        self,
        credentials_path: str | os.PathLike[str],
        lockout_threshold: int = 5,
        lockout_window_seconds: int = 15 * 60,
    ) -> None:
        self.path = Path(credentials_path)
        self.lockout_threshold = lockout_threshold
        self.lockout_window = lockout_window_seconds
        self._hasher = PasswordHasher()
        self._lock = threading.RLock()
        self._attempts: dict[str, _Attempts] = {}

    # --- credentials.json I/O -------------------------------------------

    def _read(self) -> dict:
        if not self.path.exists():
            return {"users": []}
        try:
            data = json.loads(self.path.read_text())
        except json.JSONDecodeError as e:
            raise ValueError(f"{self.path}: invalid JSON: {e}") from e
        if not isinstance(data, dict) or "users" not in data:
            raise ValueError(f"{self.path}: top-level object must have 'users'")
        return data

    def _write_atomic(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def list_users(self) -> list[dict]:
        return list(self._read().get("users", []))

    def _find(self, users: list[dict], username: str) -> int:
        for i, u in enumerate(users):
            if u.get("username") == username:
                return i
        return -1

    def set_user(self, username: str, password: str, role: str = "user") -> bool:
        """Insert or replace a user. Returns True if newly created."""
        if not username or any(c.isspace() for c in username):
            raise ValueError("username must be non-empty and contain no whitespace")
        if not password:
            raise ValueError("password must be non-empty")
        with self._lock:
            data = self._read()
            users = data.setdefault("users", [])
            idx = self._find(users, username)
            pw_hash = self._hasher.hash(password)
            record = {"username": username, "password_hash": pw_hash, "role": role}
            created = idx < 0
            if created:
                users.append(record)
            else:
                users[idx] = record
            self._write_atomic(data)
            return created

    def delete_user(self, username: str) -> bool:
        with self._lock:
            data = self._read()
            users = data.setdefault("users", [])
            idx = self._find(users, username)
            if idx < 0:
                return False
            del users[idx]
            self._write_atomic(data)
            self._attempts.pop(username, None)
            return True

    # --- verification ---------------------------------------------------

    def _check_hash(self, password_hash: str, password: str) -> bool:
        if password_hash.startswith("$argon2"):
            try:
                self._hasher.verify(password_hash, password)
                return True
            except (VerifyMismatchError, InvalidHashError):
                return False
        if password_hash.startswith("$2") and _HAS_BCRYPT:
            try:
                return _bcrypt.checkpw(password.encode(), password_hash.encode())
            except Exception:
                return False
        # Unsupported hash scheme.
        raise ValueError("unsupported password hash scheme")

    def verify(self, username: str, password: str) -> VerifyResult:
        with self._lock:
            if self._is_locked_out(username):
                return VerifyResult(ok=False, failure="locked_out")
            users = self._read().get("users", [])
            idx = self._find(users, username)
            if idx < 0:
                # Perform a dummy hash check to equalize timing a bit.
                try:
                    self._hasher.verify(
                        "$argon2id$v=19$m=65536,t=3,p=4$MDAwMDAwMDA$"
                        "ZGVmYXVsdGRlZmF1bHRkZWZhdWx0ZGVmYXVsdGRlZmF1bHQ",
                        password,
                    )
                except Exception:
                    pass
                self._record_failure(username)
                return VerifyResult(ok=False, failure="unknown_user")
            record = users[idx]
            pw_hash = record.get("password_hash", "")
            try:
                ok = self._check_hash(pw_hash, password)
            except ValueError:
                return VerifyResult(ok=False, failure="bad_hash")
            if not ok:
                self._record_failure(username)
                return VerifyResult(ok=False, failure="bad_password")
            self._clear_attempts(username)
            return VerifyResult(ok=True, user=record)

    # --- lockout bookkeeping -------------------------------------------

    def _is_locked_out(self, username: str) -> bool:
        a = self._attempts.get(username)
        if not a:
            return False
        return a.locked_until > time.time()

    def _record_failure(self, username: str) -> None:
        now = time.time()
        a = self._attempts.setdefault(username, _Attempts())
        # prune outside the window
        a.failures = [t for t in a.failures if now - t <= self.lockout_window]
        a.failures.append(now)
        if len(a.failures) >= self.lockout_threshold:
            a.locked_until = now + self.lockout_window

    def _clear_attempts(self, username: str) -> None:
        self._attempts.pop(username, None)

    def failure_count(self, username: str) -> int:
        """For tests / audit."""
        a = self._attempts.get(username)
        if not a:
            return 0
        now = time.time()
        return sum(1 for t in a.failures if now - t <= self.lockout_window)
