"""Suite-wide test configuration.

The audit writer fsyncs every record (durable before a tool runs — interface-contracts.md §1.7).
On Windows each fsync costs milliseconds, which multiplied over thousands of appends dominated
the suite. Tests replace the writer's `_fsync` seam with a no-op (process-wide `os.fsync` is
untouched). Durability itself is asserted in tests/audit/test_writer.py, whose tests opt out
with the `real_fsync` marker.

Likewise werkzeug's default password hash (scrypt) costs ~0.5 s per `UserStore.add`. Tests use a
1-iteration PBKDF2 hash instead; `check_password_hash` reads the method from the stored hash, so
verification semantics are unchanged and production keeps its default.
"""

from __future__ import annotations

from typing import Any

import pytest
from werkzeug.security import generate_password_hash

import src.audit.writer as writer
import src.web.auth as auth


@pytest.fixture(autouse=True)
def skip_fsync(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    if request.node.get_closest_marker("real_fsync") is None:
        monkeypatch.setattr(writer, "_fsync", lambda fd: None)


@pytest.fixture(autouse=True)
def fast_password_hashing(monkeypatch: pytest.MonkeyPatch) -> None:
    def cheap(password: str, *args: Any, **kwargs: Any) -> str:
        return generate_password_hash(password, method="pbkdf2:sha256:1")

    monkeypatch.setattr(auth, "generate_password_hash", cheap)
