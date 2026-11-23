"""Atomic persistence for the set of currently-active forwards.

Shape on disk:
  { "active": [ {session_id, mapping_id, external_port, protocol,
                 internal_host, internal_port, lease_seconds,
                 opened_at, description}, ... ] }

Only the manager touches this. The file lets the app recover from a
crash by deleting any mapping it had opened before dying.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass
from pathlib import Path

from .backends.base import Protocol, normalize_protocol


@dataclass
class ActiveRecord:
    session_id: str
    mapping_id: str
    external_port: int
    protocol: Protocol
    internal_host: str
    internal_port: int
    lease_seconds: int
    opened_at: float
    description: str


class StateStore:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()

    def load(self) -> list[ActiveRecord]:
        with self._lock:
            if not self.path.exists():
                return []
            try:
                data = json.loads(self.path.read_text())
            except json.JSONDecodeError:
                return []
            out: list[ActiveRecord] = []
            for row in data.get("active", []):
                try:
                    out.append(
                        ActiveRecord(
                            session_id=str(row["session_id"]),
                            mapping_id=str(row["mapping_id"]),
                            external_port=int(row["external_port"]),
                            protocol=normalize_protocol(str(row["protocol"])),
                            internal_host=str(row["internal_host"]),
                            internal_port=int(row["internal_port"]),
                            lease_seconds=int(row.get("lease_seconds", 0)),
                            opened_at=float(row.get("opened_at", 0.0)),
                            description=str(row.get("description", "")),
                        )
                    )
                except (KeyError, ValueError, TypeError):
                    # Skip malformed rows rather than refusing to start.
                    continue
            return out

    def save(self, records: list[ActiveRecord]) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(
                {"active": [asdict(r) for r in records]},
                indent=2,
            ))
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)

    def clear(self) -> None:
        self.save([])
