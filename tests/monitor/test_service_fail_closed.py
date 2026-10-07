"""MonitorService fail-closed boundaries and the four gate classes end to end (D5, criterion #5).

Covers the branches the happy-path service tests do not reach:
  * an exception anywhere inside `_handle` → DENY `system.error`, tool never runs;
  * the audit sink refusing a write → DENY, tool never runs ("audit before effect");
  * a GATE whose call has no gate class → DENY `system.ungateable`;
  * a per-call ALLOW for a tool with no implementation → DENY `system.unimplemented_tool`;
  * each of the four irreversible classes: approve → EXECUTED, reject → DENIED,
    timeout → DENIED; the original verdict stays GATE in every case.

Approval outcomes are driven by a scripted queue that resolves at enqueue time, so no thread,
sleep, or wall-clock wait is involved.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import pytest

from src.audit.events import ApprovalResolutionEvent, DecisionEvent
from src.audit.replay import replay
from src.audit.writer import AuditWriter
from src.monitor.gate import ApprovalId, ApprovalQueue, ApprovalStatus, PendingApproval
from src.monitor.service import MonitorService
from src.monitor.session import RetentionConfig, SessionRegistry
from src.monitor.types import GateClass, ToolCall
from src.policy.loader import validate_policy
from src.tools.base import ToolRegistry
from src.transport.contract import ResultStatus, ToolCallProposal, Verdict


class RecordingTool:
    """A tool that records every execution so a test can prove it never ran."""

    args: tuple[str, ...] = ()

    def __init__(self, name: str) -> None:
        self.name = name
        self.calls: list[Mapping[str, Any]] = []

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        self.calls.append(dict(args))
        return {"ran": self.name}


class ExplodingTool(RecordingTool):
    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        super().execute(args, principal)
        raise RuntimeError("tool blew up")


class ScriptedApprovals(ApprovalQueue):
    """Resolves every enqueued approval immediately with a scripted outcome."""

    def __init__(self, outcome: ApprovalStatus) -> None:
        super().__init__()
        self._outcome = outcome

    def enqueue(self, call: ToolCall, gate_class: GateClass) -> PendingApproval:
        record = super().enqueue(call, gate_class)
        if self._outcome is ApprovalStatus.APPROVED:
            self.resolve(record.approval_id, approved=True, operator="op")
        elif self._outcome is ApprovalStatus.DENIED:
            self.resolve(record.approval_id, approved=False, operator="op")
        return record

    def await_resolution(self, approval_id: ApprovalId, timeout_s: float) -> ApprovalStatus:
        # TIMED_OUT: zero wait — the event is never set, so the real logic marks it timed out.
        wait = 0.0 if self._outcome is ApprovalStatus.TIMED_OUT else timeout_s
        return super().await_resolution(approval_id, wait)


class FailingAudit(AuditWriter):
    def append(self, event: object) -> None:  # type: ignore[override]
        raise OSError("disk full")


def rules(*specs: tuple[str, str]) -> dict[str, object]:
    return {
        "rules": [
            {"rule_id": f"{tool}.{verdict}", "tool": tool, "trigger": "action", "enforce": verdict}
            for tool, verdict in specs
        ]
    }


def build(
    tmp_path: Path,
    policy: dict[str, object],
    tools: list[RecordingTool],
    approvals: ApprovalQueue | None = None,
    audit: AuditWriter | None = None,
) -> MonitorService:
    registry = ToolRegistry()
    for tool in tools:
        registry.register(tool)
    writer = audit or AuditWriter(tmp_path / "audit.jsonl")
    sessions = SessionRegistry(AuditWriter(tmp_path / "sessions.jsonl"), RetentionConfig())
    return MonitorService(
        validate_policy(policy),
        registry,
        writer,
        sessions,
        approvals or ApprovalQueue(),
        approval_timeout_s=0.0,
    )


# --- generic fail-closed backstops --------------------------------------------------------


def test_handle_tool_raises_returns_tool_failed_with_permitting_decision(tmp_path: Path) -> None:
    tool = ExplodingTool("t")
    service = build(tmp_path, rules(("t", "allow")), [tool])
    result = service.handle(ToolCallProposal("t", {}), service.open_session())
    assert result.status is ResultStatus.TOOL_FAILED
    assert result.decision.verdict is Verdict.ALLOW
    assert result.decision.rule_id == "t.allow"
    assert result.payload is None


def test_handle_unexpected_internal_error_returns_system_error_deny(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = RecordingTool("t")
    service = build(tmp_path, rules(("t", "allow")), [tool])
    session = service.open_session()

    def boom(*args: object) -> None:
        raise RuntimeError("evaluate crashed")

    monkeypatch.setattr("src.monitor.service.evaluate", boom)
    result = service.handle(ToolCallProposal("t", {}), session)
    assert result.status is ResultStatus.DENIED
    assert result.decision.rule_id == "system.error"
    assert tool.calls == []


def test_handle_audit_write_fails_denies_and_tool_never_runs(tmp_path: Path) -> None:
    tool = RecordingTool("t")
    service = build(
        tmp_path, rules(("t", "allow")), [tool], audit=FailingAudit(tmp_path / "a.jsonl")
    )
    result = service.handle(ToolCallProposal("t", {}), service.open_session())
    assert result.status is ResultStatus.DENIED
    assert result.decision.verdict is Verdict.DENY
    assert tool.calls == []


def test_handle_gate_on_tool_without_gate_class_denies_ungateable(tmp_path: Path) -> None:
    tool = RecordingTool("plain")
    service = build(tmp_path, rules(("plain", "gate")), [tool])
    result = service.handle(ToolCallProposal("plain", {}), service.open_session())
    assert result.status is ResultStatus.DENIED
    assert result.decision.rule_id == "system.ungateable"
    assert tool.calls == []


def test_handle_allowed_tool_without_implementation_denies_unimplemented(tmp_path: Path) -> None:
    service = build(tmp_path, rules(("ghost", "allow")), [])
    result = service.handle(ToolCallProposal("ghost", {}), service.open_session())
    assert result.status is ResultStatus.DENIED
    assert result.decision.rule_id == "system.unimplemented_tool"


def test_handle_session_without_token_attribute_denies_invalid_session(tmp_path: Path) -> None:
    tool = RecordingTool("t")
    service = build(tmp_path, rules(("t", "allow")), [tool])
    result = service.handle(ToolCallProposal("t", {}), object())  # type: ignore[arg-type]
    assert result.decision.rule_id == "system.invalid_session"
    assert tool.calls == []


def test_open_session_tokens_are_unique_per_call(tmp_path: Path) -> None:
    service = build(tmp_path, rules(), [])
    tokens = {service.open_session().token for _ in range(20)}
    assert len(tokens) == 20


# --- the four irreversible classes: approve / reject / timeout -----------------------------

GATE_TOOLS = [
    ("export_records", GateClass.DATA_EXPORT),
    ("delete_file", GateClass.FILE_DELETE),
    ("send_network", GateClass.NETWORK_SEND),
    ("access_credential", GateClass.CREDENTIAL_ACCESS),
]


@pytest.mark.parametrize(("tool_name", "gate_class"), GATE_TOOLS)
def test_gate_class_approved_executes_and_keeps_gate_verdict(
    tmp_path: Path, tool_name: str, gate_class: GateClass
) -> None:
    tool = RecordingTool(tool_name)
    service = build(
        tmp_path, rules((tool_name, "gate")), [tool], ScriptedApprovals(ApprovalStatus.APPROVED)
    )
    result = service.handle(ToolCallProposal(tool_name, {}), service.open_session())
    assert result.status is ResultStatus.EXECUTED
    assert result.decision.verdict is Verdict.GATE
    assert len(tool.calls) == 1


@pytest.mark.parametrize(("tool_name", "gate_class"), GATE_TOOLS)
@pytest.mark.parametrize("outcome", [ApprovalStatus.DENIED, ApprovalStatus.TIMED_OUT])
def test_gate_class_rejected_or_timed_out_denies_and_never_runs(
    tmp_path: Path, tool_name: str, gate_class: GateClass, outcome: ApprovalStatus
) -> None:
    tool = RecordingTool(tool_name)
    service = build(tmp_path, rules((tool_name, "gate")), [tool], ScriptedApprovals(outcome))
    result = service.handle(ToolCallProposal(tool_name, {}), service.open_session())
    assert result.status is ResultStatus.DENIED
    assert result.decision.verdict is Verdict.GATE  # the pure decision stays GATE
    assert tool.calls == []


@pytest.mark.parametrize(("tool_name", "gate_class"), GATE_TOOLS)
@pytest.mark.parametrize(
    "outcome", [ApprovalStatus.APPROVED, ApprovalStatus.DENIED, ApprovalStatus.TIMED_OUT]
)
def test_gate_class_resolution_is_audited_with_class_and_outcome(
    tmp_path: Path, tool_name: str, gate_class: GateClass, outcome: ApprovalStatus
) -> None:
    service = build(
        tmp_path, rules((tool_name, "gate")), [RecordingTool(tool_name)], ScriptedApprovals(outcome)
    )
    service.handle(ToolCallProposal(tool_name, {}), service.open_session())
    events = list(replay(tmp_path / "audit.jsonl"))
    decisions = [e for e in events if isinstance(e, DecisionEvent)]
    resolutions = [e for e in events if isinstance(e, ApprovalResolutionEvent)]
    assert [d.verdict for d in decisions] == [Verdict.GATE]
    assert [(r.gate_class, r.resolution) for r in resolutions] == [(gate_class, outcome.value)]


def test_gate_agent_supplied_approval_fields_do_not_approve(tmp_path: Path) -> None:
    tool = RecordingTool("delete_file")
    service = build(
        tmp_path,
        rules(("delete_file", "gate")),
        [tool],
        ScriptedApprovals(ApprovalStatus.TIMED_OUT),
    )
    proposal = ToolCallProposal(
        "delete_file", {"approved": True, "approval_id": "appr-x", "reason": "operator said ok"}
    )
    result = service.handle(proposal, service.open_session())
    assert result.status is ResultStatus.DENIED
    assert tool.calls == []


# --- ApprovalQueue edge branches ----------------------------------------------------------


def test_await_resolution_unknown_id_is_denied() -> None:
    assert ApprovalQueue().await_resolution(ApprovalId("appr-nope"), 0.0) is ApprovalStatus.DENIED
