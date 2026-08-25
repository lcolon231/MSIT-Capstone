"""Append-only JSONL audit writer + argument hashing.

Append-only is a property to test (spec.md T8.3): a mid-file edit must be detectable. The
writer never rewrites or truncates; it only appends one line per event.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from src.audit.events import AuditEvent


def hash_arguments(args: Mapping[str, Any]) -> str:
    """Stable sha256 over canonicalized call arguments. Arguments are hashed, never logged in
    plaintext (criterion #8) — this gives tamper-evidence and PII-free logging."""
    raise NotImplementedError


class AuditWriter:
    """Owns the append-only JSONL file handle. One instance per monitor process."""

    def __init__(self, path: Path) -> None:
        raise NotImplementedError

    def append(self, event: AuditEvent) -> None:
        """Append exactly one event as one JSONL line. Never rewrites existing content."""
        raise NotImplementedError
