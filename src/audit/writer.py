"""Append-only, hash-chained JSONL audit writer + argument hashing.

Two integrity properties, both testable (spec.md T8.3):
  - Append-only: the writer never rewrites or truncates; it only appends one line per event.
  - Tamper-evident: each line is chained to the previous one by ``prev_sha256`` (genesis for the
    first) plus a monotonic ``seq``, so a mid-file edit or a deleted line is intrinsically
    detectable by ``src.audit.chain.verify_chain`` — not only by comparison to an out-of-band copy
    (issue #56). The chain lives in the log envelope; the event types stay pure value objects.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

from src.audit.chain import envelope_line, line_sha256, resume
from src.audit.events import (
    ApprovalResolutionEvent,
    AuditEvent,
    ChainProgressEvent,
    DecisionEvent,
    ToolExecutionEvent,
    to_dict,
)
from src.monitor.types import ChainProgress, Decision, GateClass, ToolCall


def hash_arguments(args: Mapping[str, Any]) -> str:
    """Stable sha256 over canonicalized call arguments. Arguments are hashed, never logged in
    plaintext (criterion #8) — this gives tamper-evidence and PII-free logging."""
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# Indirection so the test suite can skip the (slow on Windows) fsync without touching `os`
# process-wide; production always calls the real os.fsync.
_fsync = os.fsync


def operator_digest(username: str) -> str:
    """The trusted operator identity as it appears in the audit log: a SHA-256 digest of the
    console username (interface-contracts.md §4.7 — "trusted operator digest"). Deterministic,
    so an auditor holding the user list can attribute a resolution without the log carrying
    account names in plaintext."""
    return hashlib.sha256(f"operator:{username}".encode("utf-8")).hexdigest()


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


def approval_resolution_event(
    call: ToolCall,
    gate_class: GateClass,
    approval_id: str,
    resolution: str,
    operator: str | None,
    timestamp: float | None = None,
) -> ApprovalResolutionEvent:
    """Build the SEPARATE event recorded when a GATE is resolved (approved/denied/timed_out).
    The original DecisionEvent keeps its GATE verdict; this records only the resolution."""
    return ApprovalResolutionEvent(
        approval_id=approval_id,
        call_id=str(call.call_id),
        session_id=call.session_id,
        principal=call.principal,
        tool=call.tool,
        arg_sha256=hash_arguments(call.args),
        gate_class=gate_class,
        resolution=resolution,
        operator=operator,
        timestamp=call.timestamp if timestamp is None else timestamp,
    )


def tool_execution_event(
    call: ToolCall, status: str, payload: Any = None, timestamp: float | None = None
) -> ToolExecutionEvent:
    """Record what a permitted call's tool did: "executed" (with a payload digest) or "failed"."""
    return ToolExecutionEvent(
        call_id=str(call.call_id),
        session_id=call.session_id,
        principal=call.principal,
        tool=call.tool,
        status=status,
        result_sha256=hash_arguments({"result": payload}) if status == "executed" else None,
        timestamp=call.timestamp if timestamp is None else timestamp,
    )


def chain_progress_event(
    call: ToolCall, from_node: str, progress: ChainProgress, timestamp: float | None = None
) -> ChainProgressEvent:
    """Record one chain moving (or re-binding) for the call's subject. `progress.bindings`
    already holds canonical digests (sequence.py never stores plaintext), copied by name."""
    return ChainProgressEvent(
        session_id=call.session_id,
        principal=call.principal,
        chain=progress.chain,
        from_node=from_node,
        to_node=progress.node,
        bindings=dict(progress.bindings),
        timestamp=call.timestamp if timestamp is None else timestamp,
    )


class AuditWriter:
    """Owns the append-only JSONL file handle and the hash-chain head. One instance per monitor
    process; a fresh instance re-opening an existing log resumes its chain (``chain.resume``)."""

    def __init__(self, path: Path, durable: bool = True) -> None:
        self._path = Path(path)
        self._durable = durable
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_sha256, self._seq = resume(self._path)

    def append(self, event: AuditEvent) -> None:
        """Append exactly one event as one chained JSONL line. Never rewrites existing content;
        the written line carries ``prev_sha256`` + ``seq`` and seeds the chain for the next."""
        line = envelope_line(to_dict(event), self._prev_sha256, self._seq)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            if self._durable:
                # "Durably appended before any permitted tool executes" (interface-contracts.md
                # §1.7): push the record past the OS cache, not just the Python buffer.
                handle.flush()
                _fsync(handle.fileno())
        self._prev_sha256 = line_sha256(line)
        self._seq += 1

    @property
    def path(self) -> Path:
        """The log this writer appends to (read by replay to seed new sessions, D15)."""
        return self._path
