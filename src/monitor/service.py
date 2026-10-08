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
from dataclasses import replace
from typing import Any, Mapping

from src.audit.events import ChainProgressEvent
from src.audit.writer import (
    AuditWriter,
    approval_resolution_event,
    chain_progress_event,
    decision_event,
    operator_digest,
    tool_execution_event,
)
from src.monitor import sequence
from src.monitor.gate import ApprovalQueue, ApprovalStatus, classify_gate
from src.monitor.session import SessionRegistry
from src.monitor.types import CallId, Decision, Principal, SequenceState, SessionId, ToolCall
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

# The implicit start node every chain leaves on its first step (sequence-engine.md §4). The
# engine represents it as "no progress" (None); the audit log names it explicitly.
IDLE_NODE = "S0_IDLE"


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
        approval_timeout_s: float = 300.0,
    ) -> None:
        self._policy = policy
        self._tools = tools
        self._audit = audit
        self._sessions = sessions
        self._approvals = approvals
        self._approval_timeout_s = approval_timeout_s
        # Chain node depths, derived once from the immutable policy, for D15 replay seeding.
        self._node_ranks = sequence.node_ranks(policy)
        # Opaque session token -> monitor-owned (session id, resolved principal). The agent
        # holds only the token and cannot choose or forge the principal (D12.2).
        self._bindings: dict[str, tuple[SessionId, Principal]] = {}

    def open_session(self, principal: str = "client-primary") -> SessionHandle:
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
        state = self._sessions.state_for(session_id, principal, self._node_ranks)
        decision = _with_gate_class(call, evaluate(call, self._policy, state))
        self._audit.append(decision_event(call, decision))

        if decision.verdict is Verdict.DENY:
            return _result(ResultStatus.DENIED, decision)
        if decision.verdict is Verdict.GATE:
            return self._gate(call, decision, state, session_id, principal)

        # ALLOW: dispatch through the registry — the one and only execution path.
        return self._execute(call, decision, state, session_id, principal)

    def _gate(
        self,
        call: ToolCall,
        decision: Decision,
        state: SequenceState,
        session_id: SessionId,
        principal: Principal,
    ) -> ToolResult:
        """Route a GATE decision to a human and block until resolved or timeout (D5). The agent
        cannot influence this: approval is keyed on a monitor-issued id resolved via the console,
        never read from the call's arguments. The original verdict stays GATE either way."""
        gate_class = decision.gate_class
        if gate_class is None:  # unreachable: _with_gate_class turns a classless GATE into a DENY
            return _result(ResultStatus.DENIED, decision)
        pending = self._approvals.enqueue(call, gate_class)
        status = self._approvals.await_resolution(pending.approval_id, self._approval_timeout_s)
        record = self._approvals.get(pending.approval_id)
        resolver = record.operator if record is not None else None
        self._audit.append(
            approval_resolution_event(
                call,
                gate_class,
                str(pending.approval_id),
                status.value,
                # Trusted identity from the console's authenticated resolve — never from the
                # call — recorded as a digest (interface-contracts.md §4.7). None on timeout.
                operator=operator_digest(resolver) if resolver is not None else None,
                # When the resolution happened, not when the call was proposed: the gap is the
                # time the call waited on a human.
                timestamp=time.time(),
            )
        )
        if status is ApprovalStatus.APPROVED:
            # Approved: execute, but the decision's verdict remains GATE (it was gated, then
            # allowed by an operator — not a per-call ALLOW).
            return self._execute(call, decision, state, session_id, principal)
        # No approval / denied / timed out: the tool never runs (fail-closed).
        return _result(ResultStatus.DENIED, decision)

    def _execute(
        self,
        call: ToolCall,
        decision: Decision,
        state: SequenceState,
        session_id: SessionId,
        principal: Principal,
    ) -> ToolResult:
        """Dispatch a permitted call through the registry — the one and only execution path —
        then advance and commit sequence state."""
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
        try:
            payload = tool.execute(call.args, str(principal))
        except Exception:
            # The call was permitted and the tool ran, but failed: report TOOL_FAILED with the
            # permitting decision and no payload. State does NOT advance — only a successful
            # execution may move a chain forward (interface-contracts.md §4.4).
            self._audit.append(tool_execution_event(call, "failed"))
            return _result(ResultStatus.TOOL_FAILED, decision)
        # Commit live state BEFORE the post-execution audit writes: if those writes fail, the
        # live chain still records this step, so detection is never weakened (the backstop then
        # reports the audit failure as a DENY).
        next_state = sequence.advance(call, self._policy, state)
        if next_state is not state:
            self._sessions.commit(session_id, next_state)
        self._audit.append(tool_execution_event(call, "executed", payload))
        for event in _chain_progress_events(call, state, next_state):
            self._audit.append(event)
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


def _with_gate_class(call: ToolCall, decision: Decision) -> Decision:
    """Resolve a GATE decision's class BEFORE it is audited, so the logged DecisionEvent says
    which D5 class routed the call to a human. A GATE no class covers is a policy
    misconfiguration and becomes a DENY (fail-closed), which is what gets logged."""
    if decision.verdict is not Verdict.GATE or decision.gate_class is not None:
        return decision
    gate_class = classify_gate(call)
    if gate_class is None:
        return Decision(
            Verdict.DENY, "system.ungateable", "GATE without a gate class (fail-closed)"
        )
    return replace(decision, gate_class=gate_class)


def _chain_progress_events(
    call: ToolCall, before: SequenceState, after: SequenceState
) -> list[ChainProgressEvent]:
    """One ChainProgressEvent per chain whose node or bindings changed for the call's subject —
    the first-class progress records replay folds to seed a new session (D12.4, D15)."""
    if after is before:
        return []
    key = sequence.subject_of(call)
    previous = {p.chain: p for p in before.for_subject(key)}
    events = []
    for progress in after.for_subject(key):
        old = previous.get(progress.chain)
        if old is not None and (old.node, dict(old.bindings)) == (
            progress.node,
            dict(progress.bindings),
        ):
            continue
        from_node = old.node if old is not None else IDLE_NODE
        events.append(chain_progress_event(call, from_node, progress))
    return events


def _result(status: ResultStatus, decision: Decision, payload: Any = None) -> ToolResult:
    """Wrap a Decision (and optional payload) into the agent-facing ToolResult."""
    return ToolResult(
        status=status,
        decision=DecisionSummary(
            verdict=decision.verdict, rule_id=decision.rule_id, reason=decision.reason
        ),
        payload=payload,
    )
