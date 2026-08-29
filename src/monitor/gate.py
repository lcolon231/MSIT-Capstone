"""Approval gate (D5) — human-in-the-loop for four irreversible classes, fail-closed.

The gate fires for exactly: file delete, network send, data export, credential access. It
routes to a human via the operator console. No approval / timeout → DENY (D5, spec.md #5).

Tamper-resistance: the `ApprovalQueue` accepts operator decisions ONLY by monitor-issued
approval id, from the console. It never reads `approved` or a persuasive `reason` from the
call's arguments — agent output cannot flip GATE→ALLOW (spec.md §140, qa-redteam-plan.md T5.3).
This module has no import path to `agent` or transport, by design.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Mapping, NewType

from src.monitor.types import GateClass, ToolCall

ApprovalId = NewType("ApprovalId", str)

# The tool → gate-class map (D5), across the RMM / files / network / credentials domains. The
# class is derived from the call, never from agent-supplied text.
GATE_CLASS_BY_TOOL: dict[str, GateClass] = {
    "export_records": GateClass.DATA_EXPORT,
    "delete_file": GateClass.FILE_DELETE,
    "send_network": GateClass.NETWORK_SEND,
    "access_credential": GateClass.CREDENTIAL_ACCESS,
}


class ApprovalStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMED_OUT = "timed_out"  # resolves as DENY (fail-closed)


@dataclass(frozen=True)
class PendingApproval:
    """A GATE decision awaiting an operator, as the console sees it. `arg_digest` is a hash,
    not plaintext args (criterion #8)."""

    approval_id: ApprovalId
    gate_class: GateClass
    tool: str
    arg_digest: str
    created_at: float
    status: ApprovalStatus = ApprovalStatus.PENDING


def classify_gate(call: ToolCall) -> GateClass | None:
    """Return the GateClass for a call that per-call/sequence policy routed to GATE, or None if
    it is not one of the four classes. Deterministic; based on the call, not agent text."""
    return GATE_CLASS_BY_TOOL.get(call.tool)


def _arg_digest(args: Mapping[str, Any]) -> str:
    """Stable sha256 over canonicalized args — mirrors audit.writer.hash_arguments, inlined so
    this module keeps no import path to transport/agent (see module docstring)."""
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ApprovalQueue:
    """Process-owned, thread-safe queue of pending approvals. Owned by `service.py`, which
    blocks on `await_resolution`; read and resolved by the console from another thread. NOT
    importable from `agent`, and it never reads approval intent from the call's arguments —
    only a monitor-issued `approval_id` resolved via `resolve` can approve (D5)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: dict[ApprovalId, PendingApproval] = {}
        self._events: dict[ApprovalId, threading.Event] = {}

    def enqueue(self, call: ToolCall, gate_class: GateClass) -> PendingApproval:
        """Register a GATE decision awaiting a human. Returns the pending record."""
        approval_id = ApprovalId(f"appr-{uuid.uuid4().hex}")
        record = PendingApproval(
            approval_id=approval_id,
            gate_class=gate_class,
            tool=call.tool,
            arg_digest=_arg_digest(call.args),
            created_at=call.timestamp,
        )
        with self._lock:
            self._pending[approval_id] = record
            self._events[approval_id] = threading.Event()
        return record

    def list_pending(self) -> tuple[PendingApproval, ...]:
        """All currently-pending approvals, for the console feed."""
        with self._lock:
            return tuple(
                r for r in self._pending.values() if r.status is ApprovalStatus.PENDING
            )

    def get(self, approval_id: ApprovalId) -> PendingApproval | None:
        """The record for an id, whatever its status (console detail view)."""
        with self._lock:
            return self._pending.get(approval_id)

    def resolve(self, approval_id: ApprovalId, approved: bool, operator: str) -> PendingApproval:
        """Operator decision, keyed by monitor-issued approval id. Only channel that can approve
        a gated call — never the agent. Idempotent: a resolved approval is returned unchanged."""
        with self._lock:
            record = self._pending.get(approval_id)
            if record is None:
                raise KeyError(approval_id)
            if record.status is ApprovalStatus.PENDING:
                status = ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED
                record = replace(record, status=status)
                self._pending[approval_id] = record
                event = self._events.get(approval_id)
            else:
                event = None
        if event is not None:
            event.set()
        return record

    def await_resolution(self, approval_id: ApprovalId, timeout_s: float) -> ApprovalStatus:
        """Block until resolved or timeout. Timeout resolves as TIMED_OUT (DENY, fail-closed)."""
        with self._lock:
            event = self._events.get(approval_id)
        if event is None:
            return ApprovalStatus.DENIED  # unknown id fails closed
        signalled = event.wait(timeout_s)
        with self._lock:
            record = self._pending.get(approval_id)
            if record is None:
                return ApprovalStatus.DENIED
            if not signalled and record.status is ApprovalStatus.PENDING:
                record = replace(record, status=ApprovalStatus.TIMED_OUT)
                self._pending[approval_id] = record
            return record.status
