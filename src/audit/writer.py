"""Append-only JSONL audit writer + argument hashing.

Append-only is a property to test (spec.md T8.3): a mid-file edit must be detectable. The
writer never rewrites or truncates; it only appends one line per event.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from src.audit.events import AuditEvent, DecisionEvent, to_jsonl
from src.monitor.types import Decision, ToolCall


def hash_arguments(args: Mapping[str, Any]) -> str:
    """Stable sha256 over canonicalized call arguments. Arguments are hashed, never logged in
    plaintext (criterion #8) — this gives tamper-evidence and PII-free logging."""
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def decision_event(
    call: ToolCall, decision: Decision, timestamp: float | None = None
) -> DecisionEvent:
    """Build the one DecisionEvent recorded per verdict. Arguments are hashed, not stored."""
    return DecisionEvent(
        call_id=str(call.call_id),
        session_id=call.session_id,
        principal=call.principal,
        tool=call.tool,
        arg_sha256=hash_arguments(call.args),
        verdict=decision.verdict,
        rule_id=decision.rule_id,
        reason=decision.reason,
        gate_class=decision.gate_class,
        timestamp=call.timestamp if timestamp is None else timestamp,
    )


class AuditWriter:
    """Owns the append-only JSONL file handle. One instance per monitor process."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: AuditEvent) -> None:
        """Append exactly one event as one JSONL line. Never rewrites existing content."""
        line = to_jsonl(event)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
