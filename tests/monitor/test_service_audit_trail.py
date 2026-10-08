"""The audit trail a mediated call leaves behind (interface-contracts.md §4.7 event table).

* every permitted call that reaches its tool writes a ToolExecutionEvent: "executed" with a
  payload digest, or "failed" with none — and a DENY writes none;
* every chain advance writes a ChainProgressEvent with NAMED binding digests (no plaintext);
* a repeated step that re-binds writes a from == to event; an unmatched call writes none;
* an approval resolution records the resolving operator as a digest, never from the call;
* if the post-execution audit write fails, live chain state is still committed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.audit.events import (
    ApprovalResolutionEvent,
    AuditEvent,
    ChainProgressEvent,
    DecisionEvent,
    ToolExecutionEvent,
)
from src.audit.replay import replay
from src.audit.writer import AuditWriter, hash_arguments, operator_digest
from src.monitor.gate import ApprovalId, ApprovalQueue, ApprovalStatus, PendingApproval
from src.monitor.sequence import _canonical_digest
from src.monitor.service import IDLE_NODE, MonitorService
from src.monitor.session import RetentionConfig, SessionRegistry
from src.monitor.types import GateClass, ToolCall
from src.policy.loader import load_policy
from src.tools import rmm
from src.tools.base import ToolRegistry
from src.tools.rmm import EndpointState, register_rmm
from src.transport.contract import ResultStatus, SessionHandle, ToolCallProposal

REPO_ROOT = Path(__file__).resolve().parents[2]
RMM = REPO_ROOT / "policies" / "rmm.yaml"
PRINCIPAL = "client-1"


class ResolvingQueue(ApprovalQueue):
    """Resolves each enqueued approval immediately as `operator` (None → time out)."""

    def __init__(self, operator: str | None, approved: bool = True) -> None:
        super().__init__()
        self._operator, self._approved = operator, approved

    def enqueue(self, call: ToolCall, gate_class: GateClass) -> PendingApproval:
        record = super().enqueue(call, gate_class)
        if self._operator is not None:
            self.resolve(record.approval_id, approved=self._approved, operator=self._operator)
        return record

    def await_resolution(self, approval_id: ApprovalId, timeout_s: float) -> ApprovalStatus:
        return super().await_resolution(approval_id, 0.0)


class AuditFailsAfter(AuditWriter):
    """Accepts the first `n` appends, then refuses every later one."""

    def __init__(self, path: Path, n: int) -> None:
        super().__init__(path)
        self._left = n

    def append(self, event: AuditEvent) -> None:
        if self._left <= 0:
            raise OSError("disk full")
        self._left -= 1
        super().append(event)


def build(
    tmp_path: Path, approvals: ApprovalQueue | None = None, audit: AuditWriter | None = None
) -> tuple[MonitorService, SessionRegistry, SessionHandle]:
    registry = ToolRegistry()
    register_rmm(
        registry,
        EndpointState(
            endpoints={PRINCIPAL: ["ep-1"]},
            shares={PRINCIPAL: ["records"]},
            destinations={PRINCIPAL: ["approved-dest"]},
        ),
    )
    writer = audit or AuditWriter(tmp_path / "audit.jsonl")
    sessions = SessionRegistry(writer, RetentionConfig())
    service = MonitorService(
        load_policy(RMM), registry, writer, sessions, approvals or ApprovalQueue(), 0.0
    )
    return service, sessions, service.open_session(PRINCIPAL)


def events(tmp_path: Path, kind: type) -> list:
    return [e for e in replay(tmp_path / "audit.jsonl") if isinstance(e, kind)]


def run(service: MonitorService, session: SessionHandle, *steps: tuple[str, dict]) -> None:
    for tool, args in steps:
        service.handle(ToolCallProposal(tool, args), session)


# --- ToolExecutionEvent -------------------------------------------------------------------


def test_executed_call_writes_executed_event_with_payload_digest(tmp_path: Path) -> None:
    service, _, session = build(tmp_path)
    result = service.handle(ToolCallProposal("list_endpoints", {}), session)
    (event,) = events(tmp_path, ToolExecutionEvent)
    (decision,) = events(tmp_path, DecisionEvent)
    assert (event.status, event.tool, event.call_id) == (
        "executed",
        "list_endpoints",
        decision.call_id,
    )
    assert event.result_sha256 == hash_arguments({"result": result.payload})


def test_failed_tool_writes_failed_event_without_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(self: object, args: object, principal: str) -> object:
        raise RuntimeError("boom")

    monkeypatch.setattr(rmm.ListEndpoints, "execute", explode)
    service, _, session = build(tmp_path)
    assert service.handle(ToolCallProposal("list_endpoints", {}), session).status is (
        ResultStatus.TOOL_FAILED
    )
    (event,) = events(tmp_path, ToolExecutionEvent)
    assert (event.status, event.result_sha256) == ("failed", None)


@pytest.mark.parametrize(
    "proposal",
    [ToolCallProposal("disable_logging", {}), ToolCallProposal("nope", {})],
    ids=["explicit-deny", "unknown-tool"],
)
def test_denied_call_writes_no_execution_event(tmp_path: Path, proposal: ToolCallProposal) -> None:
    service, _, session = build(tmp_path)
    service.handle(proposal, session)
    assert events(tmp_path, ToolExecutionEvent) == []


def test_decision_event_precedes_execution_event(tmp_path: Path) -> None:
    service, _, session = build(tmp_path)
    service.handle(ToolCallProposal("list_endpoints", {}), session)
    kinds = [type(e) for e in replay(tmp_path / "audit.jsonl")]
    assert kinds.index(DecisionEvent) < kinds.index(ToolExecutionEvent)


# --- ChainProgressEvent -------------------------------------------------------------------


def test_each_chain_advance_writes_one_progress_event_in_order(tmp_path: Path) -> None:
    service, _, session = build(tmp_path)
    run(
        service,
        session,
        ("list_endpoints", {}),
        ("list_shares", {}),
        ("register_destination", {"destination": "attacker-dropbox"}),
    )
    progress = events(tmp_path, ChainProgressEvent)
    assert [(e.from_node, e.to_node) for e in progress] == [
        (IDLE_NODE, "S1_ENDPOINTS"),
        ("S1_ENDPOINTS", "S2_SHARES"),
        ("S2_SHARES", "S3_DESTINATION_ADDED"),
    ]
    assert {e.chain for e in progress} == {"recon_register_exfil"}
    assert progress[-1].bindings == {
        "registered_destination": _canonical_digest("attacker-dropbox")
    }


def test_progress_events_never_contain_plaintext_bound_values(tmp_path: Path) -> None:
    service, _, session = build(tmp_path)
    run(
        service,
        session,
        ("list_endpoints", {}),
        ("list_shares", {}),
        ("register_destination", {"destination": "attacker-dropbox"}),
    )
    assert "attacker-dropbox" not in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")


def test_repeated_register_rebinds_and_writes_same_node_event(tmp_path: Path) -> None:
    service, _, session = build(tmp_path)
    run(
        service,
        session,
        ("list_endpoints", {}),
        ("list_shares", {}),
        ("register_destination", {"destination": "first"}),
        ("register_destination", {"destination": "second"}),
    )
    last = events(tmp_path, ChainProgressEvent)[-1]
    assert (last.from_node, last.to_node) == ("S3_DESTINATION_ADDED", "S3_DESTINATION_ADDED")
    assert last.bindings == {"registered_destination": _canonical_digest("second")}


def test_repeated_step_with_no_change_writes_no_progress_event(tmp_path: Path) -> None:
    service, _, session = build(tmp_path)
    run(service, session, ("list_endpoints", {}), ("list_endpoints", {}))
    assert len(events(tmp_path, ChainProgressEvent)) == 1


def test_unmatched_executed_call_writes_no_progress_event(tmp_path: Path) -> None:
    service, _, session = build(tmp_path)
    run(service, session, ("list_shares", {}))  # S0 → no list_shares transition
    assert events(tmp_path, ChainProgressEvent) == []


# --- operator identity on approval resolution ---------------------------------------------


@pytest.mark.parametrize(("approved", "resolution"), [(True, "approved"), (False, "denied")])
def test_resolution_records_operator_digest(
    tmp_path: Path, approved: bool, resolution: str
) -> None:
    service, _, session = build(tmp_path, ResolvingQueue("alice", approved))
    service.handle(ToolCallProposal("export_records", {"to": "approved-dest"}), session)
    (event,) = events(tmp_path, ApprovalResolutionEvent)
    assert (event.resolution, event.operator) == (resolution, operator_digest("alice"))
    assert "alice" not in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")


def test_timed_out_resolution_has_no_operator(tmp_path: Path) -> None:
    service, _, session = build(tmp_path, ResolvingQueue(None))
    service.handle(ToolCallProposal("export_records", {"to": "approved-dest"}), session)
    (event,) = events(tmp_path, ApprovalResolutionEvent)
    assert (event.resolution, event.operator) == ("timed_out", None)


def test_operator_named_in_call_arguments_is_ignored(tmp_path: Path) -> None:
    service, _, session = build(tmp_path, ResolvingQueue("alice"))
    service.handle(
        ToolCallProposal("export_records", {"to": "approved-dest", "operator": "mallory"}),
        session,
    )
    (event,) = events(tmp_path, ApprovalResolutionEvent)
    assert event.operator == operator_digest("alice")


def test_queue_records_resolving_operator_on_the_pending_record() -> None:
    queue = ApprovalQueue()
    call = ToolCall("export_records", {}, "s", "p", "c", 0.0)  # type: ignore[arg-type]
    record = queue.enqueue(call, GateClass.DATA_EXPORT)
    assert record.operator is None
    assert queue.resolve(record.approval_id, approved=True, operator="bob").operator == "bob"


def test_gate_decision_record_carries_its_gate_class(tmp_path: Path) -> None:
    service, _, session = build(tmp_path, ResolvingQueue("alice"))
    service.handle(ToolCallProposal("export_records", {"to": "approved-dest"}), session)
    (decision,) = events(tmp_path, DecisionEvent)
    (resolution,) = events(tmp_path, ApprovalResolutionEvent)
    assert decision.gate_class is GateClass.DATA_EXPORT
    assert resolution.gate_class is decision.gate_class


def test_resolution_is_stamped_when_resolved_not_when_proposed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import src.monitor.service as service_mod

    clock = iter([100.0, 160.0])  # proposal enrichment, then the resolution write
    monkeypatch.setattr(service_mod.time, "time", lambda: next(clock))
    service, _, session = build(tmp_path, ResolvingQueue("alice"))
    service.handle(ToolCallProposal("export_records", {"to": "approved-dest"}), session)
    (decision,) = events(tmp_path, DecisionEvent)
    (resolution,) = events(tmp_path, ApprovalResolutionEvent)
    assert (decision.timestamp, resolution.timestamp) == (100.0, 160.0)


# --- ordering under audit failure ---------------------------------------------------------


def test_post_execution_audit_failure_still_commits_live_chain_state(tmp_path: Path) -> None:
    # Allow: session-open + DecisionEvent; refuse the ToolExecutionEvent that follows.
    writer = AuditFailsAfter(tmp_path / "audit.jsonl", n=2)
    service, sessions, session = build(tmp_path, audit=writer)
    result = service.handle(ToolCallProposal("list_endpoints", {}), session)
    assert result.status is ResultStatus.DENIED  # the audit failure is reported fail-closed
    nodes = [p.node for chains in sessions.live_state().progress.values() for p in chains]
    assert nodes == ["S1_ENDPOINTS"]  # detection kept the step the tool already took
