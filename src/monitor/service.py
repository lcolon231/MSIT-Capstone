"""The enforcement composition root — the decision-and-dispatch endpoint (D11).

`MonitorService.handle` is the ONLY path through which a tool executes (complete mediation).
It ties together every enforcement component; it is the one place with side effects.

Single-call flow (docs/design/diagrams/05-single-call-dataflow.mmd):
    1. enrich proposal → ToolCall  (assign session id, resolve principal, stamp time)
    2. decision = evaluate(call, policy, state)          [pure]
    3. write DecisionEvent to audit                       [args hashed]
    4. GATE  → enqueue, await operator; timeout → DENY
       DENY  → return denied result (tool never runs)
       ALLOW / approved GATE → dispatch to tool via registry
    5. on execution: advance sequence state, write ChainProgressEvent, commit state
    6. return ToolResult over the transport

Complete mediation guarantee: a malformed/unknown proposal still yields a Decision (DENY),
never an exception that crashes open (spec.md criterion #1, qa-redteam-plan.md T1.3).
"""

from __future__ import annotations

from src.audit.writer import AuditWriter
from src.monitor.gate import ApprovalQueue
from src.monitor.session import SessionRegistry
from src.policy.schema import Policy
from src.tools.base import ToolRegistry
from src.transport.contract import SessionHandle, ToolCallProposal, ToolResult


class MonitorService:
    """Owns policy, sequence state, the approval queue, the audit writer, and the tool registry.
    Injected into the transports (in-process / loopback); never imports `agent`."""

    def __init__(
        self,
        policy: Policy,
        tools: ToolRegistry,
        audit: AuditWriter,
        sessions: SessionRegistry,
        approvals: ApprovalQueue,
    ) -> None:
        raise NotImplementedError

    def open_session(self) -> SessionHandle:
        """Assign a new session (D12.2) and return its opaque handle to the caller."""
        raise NotImplementedError

    def handle(self, proposal: ToolCallProposal, session: SessionHandle) -> ToolResult:
        """Evaluate, log, gate/execute, advance, and return — the full mediated flow. A
        malformed proposal or unknown tool yields a DENY ToolResult, never an exception."""
        raise NotImplementedError
