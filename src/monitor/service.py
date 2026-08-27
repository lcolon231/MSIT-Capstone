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

import time
import uuid
from typing import Any, Mapping

from src.audit.writer import AuditWriter, decision_event
from src.monitor import sequence
from src.monitor.gate import ApprovalQueue
from src.monitor.session import SessionRegistry
from src.monitor.types import CallId, Decision, Principal, SessionId, ToolCall
from src.monitor.verdict import evaluate
from src.policy.schema import Policy
from src.tools.base import ToolRegistry
from src.transport.contract import (
    DecisionSummary,
    ResultStatus,
    SessionHandle,
    ToolCallProposal,
    ToolResult,
    Verdict,
)


class MonitorService:
    """Owns policy, sequence state, the approval queue, the audit writer, and the tool registry.
    Injected into the transports (in-process / loopback); never imports `agent`.

    `handle` is the ONLY path through which a tool executes (complete mediation, criterion #1):
    every proposal yields a Decision, is audited, and reaches the tool registry only on ALLOW.
    A malformed proposal, an unknown/unimplemented tool, or an invalid session all fail closed
    to a DENY ToolResult — never an exception that crashes the monitor open.
    """

    def __init__(
        self,
        policy: Policy,
        tools: ToolRegistry,
        audit: AuditWriter,
        sessions: SessionRegistry,
        approvals: ApprovalQueue,
    ) -> None:
        self._policy = policy
        self._tools = tools
        self._audit = audit
        self._sessions = sessions
        self._approvals = approvals  # queue wiring / await is issue #13 (T4.1)
        # Opaque session token -> monitor-owned (session id, resolved principal). The agent
        # holds only the token and cannot choose or forge the principal (D12.2).
        self._bindings: dict[str, tuple[SessionId, Principal]] = {}

    def open_session(self, principal: str = "acct-primary") -> SessionHandle:
        """Assign a new session (D12.2) bound to a resolved principal and return its opaque
        handle. The principal is session-bound, not read from any per-call argument."""
        session_id = self._sessions.open_session()
        token = uuid.uuid4().hex
        self._bindings[token] = (session_id, Principal(principal))
        return SessionHandle(token=token)

    def handle(self, proposal: ToolCallProposal, session: SessionHandle) -> ToolResult:
        """Evaluate, log, gate/execute, advance, and return — the full mediated flow. A
        malformed proposal or unknown tool yields a DENY ToolResult, never an exception."""
        try:
            return self._handle(proposal, session)
        except Exception:
            # Absolute fail-closed backstop: no proposal may crash the monitor open.
            return _result(
                ResultStatus.DENIED,
                Decision(Verdict.DENY, "system.error", "monitor error (fail-closed)"),
            )

    def _handle(self, proposal: ToolCallProposal, session: SessionHandle) -> ToolResult:
        binding = self._bindings.get(getattr(session, "token", None))  # type: ignore[arg-type]
        if binding is None:
            return _result(
                ResultStatus.DENIED,
                Decision(Verdict.DENY, "system.invalid_session", "unknown session (fail-closed)"),
            )
        session_id, principal = binding

        call = self._enrich(proposal, session_id, principal)
        state = self._sessions.state_for(session_id, principal)
        decision = evaluate(call, self._policy, state)
        self._audit.append(decision_event(call, decision))

        if decision.verdict is Verdict.DENY:
            return _result(ResultStatus.DENIED, decision)
        if decision.verdict is Verdict.GATE:
            # The call does not execute. Approval queueing + await lands in issue #13 (T4.1);
            # until then a gated call is reported pending and the tool never runs.
            return _result(ResultStatus.GATED_PENDING, decision)

        # ALLOW: dispatch through the registry — the one and only execution path.
        tool = self._tools.get(call.tool)
        if tool is None:
            return _result(
                ResultStatus.DENIED,
                Decision(
                    Verdict.DENY,
                    "system.unimplemented_tool",
                    "allowed tool has no implementation (fail-closed)",
                ),
            )
        payload = tool.execute(call.args, str(principal))
        next_state = sequence.advance(call, self._policy, state)
        if next_state is not state:
            self._sessions.commit(session_id, next_state)
        return _result(ResultStatus.EXECUTED, decision, payload)

    def _enrich(
        self, proposal: ToolCallProposal, session_id: SessionId, principal: Principal
    ) -> ToolCall:
        """Normalize the agent proposal into a monitor-enriched ToolCall: monitor-assigned
        session, resolved principal, fresh call id, and monitor-side timestamp. Never trusts
        the proposal for identity; a non-mapping `args` normalizes to empty (fail-closed)."""
        raw_args = proposal.args
        args: Mapping[str, Any] = dict(raw_args) if isinstance(raw_args, Mapping) else {}
        return ToolCall(
            tool=str(proposal.tool),
            args=args,
            session_id=session_id,
            principal=principal,
            call_id=CallId(uuid.uuid4().hex),
            timestamp=time.time(),
        )


def _result(status: ResultStatus, decision: Decision, payload: Any = None) -> ToolResult:
    """Wrap a Decision (and optional payload) into the agent-facing ToolResult."""
    return ToolResult(
        status=status,
        decision=DecisionSummary(
            verdict=decision.verdict, rule_id=decision.rule_id, reason=decision.reason
        ),
        payload=payload,
    )
