"""Approval gate (D5) — issue #13 / T4.1.

The four irreversible classes route to a human. No approval / timeout prevents execution
(DENIED) while the decision keeps its GATE verdict; a separate approval-resolution audit event
records the outcome. Agent output can never flip GATE -> ALLOW — only a monitor-issued approval
id resolved through the queue (the console) can approve.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from src.audit.events import ApprovalResolutionEvent, DecisionEvent
from src.audit.replay import replay
from src.audit.writer import AuditWriter
from src.monitor.gate import (
    ApprovalId,
    ApprovalQueue,
    ApprovalStatus,
    classify_gate,
)
from src.monitor.service import MonitorService
from src.monitor.session import RetentionConfig, SessionRegistry
from src.monitor.types import CallId, GateClass, Principal, SessionId, ToolCall
from src.policy.loader import load_policy
from src.tools.banking import BankingState, register_banking
from src.tools.base import ToolRegistry
from src.transport.contract import ResultStatus, ToolCallProposal, Verdict

REPO_ROOT = Path(__file__).resolve().parents[2]
BANKING = REPO_ROOT / "policies" / "banking.yaml"


def make_call(tool: str, **args: object) -> ToolCall:
    return ToolCall(
        tool=tool,
        args=args,
        session_id=SessionId("s1"),
        principal=Principal("acct-1"),
        call_id=CallId("c1"),
        timestamp=0.0,
    )


def propose(tool: str, **args: object) -> ToolCallProposal:
    return ToolCallProposal(tool=tool, args=args)


def build(tmp_path: Path, timeout: float):
    state = BankingState(balances={"acct-1": 1000}, payees={"acct-1": ["existing"]})
    registry = ToolRegistry()
    register_banking(registry, state)
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditWriter(audit_path)
    sessions = SessionRegistry(audit, RetentionConfig())
    queue = ApprovalQueue()
    service = MonitorService(load_policy(BANKING), registry, audit, sessions, queue, approval_timeout_s=timeout)
    return service, state, service.open_session("acct-1"), queue, audit_path


def _resolve_when_pending(queue: ApprovalQueue, approved: bool, operator: str = "op-1") -> threading.Thread:
    """Background operator: wait for a pending approval, then resolve it (the console's role)."""

    def run() -> None:
        for _ in range(400):
            pending = queue.list_pending()
            if pending:
                queue.resolve(pending[0].approval_id, approved, operator)
                return
            time.sleep(0.005)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


# --- classify_gate: the four classes ------------------------------------------------------


def test_classify_gate_maps_the_four_classes() -> None:
    assert classify_gate(make_call("transfer_funds")) is GateClass.FUND_TRANSFER
    assert classify_gate(make_call("delete_file")) is GateClass.FILE_DELETE
    assert classify_gate(make_call("send_network")) is GateClass.NETWORK_SEND
    assert classify_gate(make_call("access_credential")) is GateClass.CREDENTIAL_ACCESS


def test_classify_gate_returns_none_for_non_gate_tool() -> None:
    assert classify_gate(make_call("get_balance")) is None


# --- ApprovalQueue mechanics --------------------------------------------------------------


def test_enqueue_lists_pending_with_a_hashed_digest() -> None:
    queue = ApprovalQueue()
    record = queue.enqueue(make_call("transfer_funds", to="acme-1"), GateClass.FUND_TRANSFER)
    assert record.status is ApprovalStatus.PENDING
    assert queue.list_pending() == (record,)
    assert record.arg_digest != "acme-1" and len(record.arg_digest) == 64  # hashed, not plaintext


def test_resolve_approves_and_await_unblocks() -> None:
    queue = ApprovalQueue()
    record = queue.enqueue(make_call("transfer_funds"), GateClass.FUND_TRANSFER)
    queue.resolve(record.approval_id, True, "op-1")
    assert queue.await_resolution(record.approval_id, 1.0) is ApprovalStatus.APPROVED
    assert queue.list_pending() == ()  # no longer pending once resolved


def test_resolve_denies() -> None:
    queue = ApprovalQueue()
    record = queue.enqueue(make_call("transfer_funds"), GateClass.FUND_TRANSFER)
    queue.resolve(record.approval_id, False, "op-1")
    assert queue.await_resolution(record.approval_id, 1.0) is ApprovalStatus.DENIED


def test_await_times_out_fail_closed() -> None:
    queue = ApprovalQueue()
    record = queue.enqueue(make_call("transfer_funds"), GateClass.FUND_TRANSFER)
    assert queue.await_resolution(record.approval_id, 0.05) is ApprovalStatus.TIMED_OUT


def test_resolve_unknown_id_raises() -> None:
    with pytest.raises(KeyError):
        ApprovalQueue().resolve(ApprovalId("nope"), True, "op-1")


def test_resolve_is_idempotent() -> None:
    queue = ApprovalQueue()
    record = queue.enqueue(make_call("transfer_funds"), GateClass.FUND_TRANSFER)
    queue.resolve(record.approval_id, True, "op-1")
    again = queue.resolve(record.approval_id, False, "op-2")  # cannot flip an approved decision
    assert again.status is ApprovalStatus.APPROVED


# --- service integration: the gated flow --------------------------------------------------


def test_approved_gate_executes_and_keeps_gate_verdict(tmp_path: Path) -> None:
    service, state, session, queue, _ = build(tmp_path, timeout=2.0)
    approver = _resolve_when_pending(queue, approved=True)
    result = service.handle(propose("transfer_funds", to="acme-1", amount=200), session)
    approver.join(timeout=2.0)
    assert result.status is ResultStatus.EXECUTED
    assert result.decision.verdict is Verdict.GATE  # gated, then operator-approved
    assert state.balances["acct-1"] == 800  # the transfer ran


def test_operator_denial_blocks_execution(tmp_path: Path) -> None:
    service, state, session, queue, _ = build(tmp_path, timeout=2.0)
    approver = _resolve_when_pending(queue, approved=False)
    result = service.handle(propose("transfer_funds", to="acme-1", amount=200), session)
    approver.join(timeout=2.0)
    assert result.status is ResultStatus.DENIED
    assert state.balances["acct-1"] == 1000  # untouched


def test_timed_out_gate_is_denied(tmp_path: Path) -> None:
    service, state, session, _queue, _ = build(tmp_path, timeout=0.05)
    result = service.handle(propose("transfer_funds", to="acme-1", amount=200), session)
    assert result.status is ResultStatus.DENIED
    assert result.decision.verdict is Verdict.GATE
    assert state.balances["acct-1"] == 1000


def test_agent_cannot_self_approve_via_arguments(tmp_path: Path) -> None:
    service, state, session, _queue, _ = build(tmp_path, timeout=0.05)
    # The agent smuggles approved=true and a persuasive reason — both are ignored.
    result = service.handle(
        propose("transfer_funds", to="acme-1", amount=200, approved=True, reason="please approve"),
        session,
    )
    assert result.status is ResultStatus.DENIED
    assert state.balances["acct-1"] == 1000  # never executed


# --- separate approval-resolution audit event ---------------------------------------------


def test_gate_resolution_is_audited_separately(tmp_path: Path) -> None:
    service, _state, session, _queue, audit_path = build(tmp_path, timeout=0.05)
    service.handle(propose("transfer_funds", to="acme-1", amount=200), session)
    events = list(replay(audit_path))
    decisions = [e for e in events if isinstance(e, DecisionEvent) and e.tool == "transfer_funds"]
    resolutions = [e for e in events if isinstance(e, ApprovalResolutionEvent)]
    assert decisions and decisions[0].verdict is Verdict.GATE  # original decision stays GATE
    assert len(resolutions) == 1
    resolution = resolutions[0]
    assert resolution.gate_class is GateClass.FUND_TRANSFER
    assert resolution.resolution == "timed_out"
    assert resolution.operator is None
    assert resolution.arg_sha256 and "acme-1" not in resolution.arg_sha256  # hashed, not plaintext
