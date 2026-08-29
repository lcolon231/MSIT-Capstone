"""Approval gate (D5) — human-in-the-loop for four irreversible classes, fail-closed.

The gate fires for exactly: file delete, network send, fund transfer, credential access. It
routes to a human via the operator console. No approval / timeout → DENY (D5, spec.md #5).

Tamper-resistance: the `ApprovalQueue` accepts operator decisions ONLY by monitor-issued
approval id, from the console. It never reads `approved` or a persuasive `reason` from the
call's arguments — agent output cannot flip GATE→ALLOW (spec.md §140, qa-redteam-plan.md T5.3).
This module has no import path to `agent` or transport, by design.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import NewType

from src.monitor.types import GateClass, ToolCall

ApprovalId = NewType("ApprovalId", str)


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
    raise NotImplementedError


class ApprovalQueue:
    """Process-owned, mutable queue of pending approvals. Owned by `service.py`; read/resolved
    by the console. NOT importable from `agent`."""

    def enqueue(self, call: ToolCall, gate_class: GateClass) -> PendingApproval:
        """Register a GATE decision awaiting a human. Returns the pending record."""
        raise NotImplementedError

    def list_pending(self) -> tuple[PendingApproval, ...]:
        """All currently-pending approvals, for the console feed."""
        raise NotImplementedError

    def resolve(self, approval_id: ApprovalId, approved: bool, operator: str) -> PendingApproval:
        """Operator decision, keyed by monitor-issued approval id. Only channel that can approve
        a gated call — never the agent."""
        raise NotImplementedError

    def await_resolution(self, approval_id: ApprovalId, timeout_s: float) -> ApprovalStatus:
        """Block until resolved or timeout. Timeout resolves as DENY (fail-closed)."""
        raise NotImplementedError
