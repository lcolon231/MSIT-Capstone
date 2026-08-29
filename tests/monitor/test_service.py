"""Mediated dispatch — issue #11 / T3.2, complete mediation (criterion #1).

Acceptance:
  * the RMM domain tools run over in-process state through the service;
  * NO tool executes without a Decision; an unknown tool is denied, not passed through;
  * a malformed proposal still yields a Decision — the monitor never crashes open.

Every path through `MonitorService.handle` returns a `ToolResult` whose `decision` carries a
non-null, traceable rule_id, and only an ALLOW ever reaches the tool registry.
"""

from __future__ import annotations

from pathlib import Path

from src.audit.writer import AuditWriter
from src.monitor.gate import ApprovalQueue
from src.monitor.service import MonitorService
from src.monitor.session import RetentionConfig, SessionRegistry
from src.policy.loader import load_policy
from src.tools.base import ToolRegistry
from src.tools.rmm import EndpointState, register_rmm
from src.transport.contract import ResultStatus, SessionHandle, ToolCallProposal, Verdict

REPO_ROOT = Path(__file__).resolve().parents[2]
RMM = REPO_ROOT / "policies" / "rmm.yaml"


def build_service(tmp_path: Path, principal: str = "client-1") -> tuple[MonitorService, EndpointState, SessionHandle]:
    state = EndpointState(
        endpoints={principal: ["ep-1"]},
        shares={principal: ["records"]},
        destinations={principal: ["approved-dest"]},
    )
    registry = ToolRegistry()
    register_rmm(registry, state)
    audit = AuditWriter(tmp_path / "audit.jsonl")
    sessions = SessionRegistry(audit, RetentionConfig())
    # Tiny approval timeout so an un-resolved GATE fails closed fast instead of blocking a test.
    service = MonitorService(
        load_policy(RMM), registry, audit, sessions, ApprovalQueue(), approval_timeout_s=0.05
    )
    return service, state, service.open_session(principal)


def propose(tool: str, **args: object) -> ToolCallProposal:
    return ToolCallProposal(tool=tool, args=args)


# --- ALLOW dispatches through to the tool -------------------------------------------------


def test_allowed_call_executes_and_returns_payload(tmp_path: Path) -> None:
    service, _state, session = build_service(tmp_path)
    result = service.handle(propose("list_endpoints"), session)
    assert result.status is ResultStatus.EXECUTED
    assert result.decision.verdict is Verdict.ALLOW
    assert result.payload == {"endpoints": ["ep-1"]}


def test_allowed_register_destination_mutates_in_process_state(tmp_path: Path) -> None:
    service, state, session = build_service(tmp_path)
    service.handle(propose("register_destination", destination="acme"), session)
    assert "acme" in state.destinations["client-1"]


# --- DENY / GATE never execute ------------------------------------------------------------


def test_unapproved_gate_does_not_execute(tmp_path: Path) -> None:
    service, state, session = build_service(tmp_path)
    # No operator resolves it -> times out -> DENIED, but the decision stays GATE.
    result = service.handle(propose("export_records", to="acme", count=200), session)
    assert result.status is ResultStatus.DENIED
    assert result.decision.verdict is Verdict.GATE
    assert state.exported == []  # nothing exported — the tool never ran


def test_explicit_deny_rule_blocks(tmp_path: Path) -> None:
    service, _state, session = build_service(tmp_path)
    result = service.handle(propose("disable_logging"), session)
    assert result.status is ResultStatus.DENIED
    assert result.decision.rule_id == "rmm.disable_logging.deny"


def test_unknown_tool_is_denied_not_passed_through(tmp_path: Path) -> None:
    service, _state, session = build_service(tmp_path)
    result = service.handle(propose("wire_to_offshore", amount=999), session)
    assert result.status is ResultStatus.DENIED
    assert result.decision.rule_id == "default"  # fail-closed default, no dispatch


# --- complete mediation: never crash open -------------------------------------------------


def test_malformed_args_still_yields_a_decision(tmp_path: Path) -> None:
    service, _state, session = build_service(tmp_path)
    # args is not a mapping — enrichment normalizes to empty and the flow still decides.
    bad = ToolCallProposal(tool="list_endpoints", args=None)  # type: ignore[arg-type]
    result = service.handle(bad, session)
    assert result.status is ResultStatus.EXECUTED
    assert result.decision.rule_id


def test_non_string_tool_is_denied_without_crashing(tmp_path: Path) -> None:
    service, _state, session = build_service(tmp_path)
    bad = ToolCallProposal(tool=123, args={})  # type: ignore[arg-type]
    result = service.handle(bad, session)
    assert result.status is ResultStatus.DENIED  # unknown tool -> default deny


def test_invalid_session_is_denied(tmp_path: Path) -> None:
    service, _state, _session = build_service(tmp_path)
    result = service.handle(propose("list_endpoints"), SessionHandle(token="forged"))
    assert result.status is ResultStatus.DENIED
    assert result.decision.rule_id == "system.invalid_session"


def test_every_result_carries_a_non_null_rule_id(tmp_path: Path) -> None:
    service, _state, session = build_service(tmp_path)
    for proposal in (
        propose("list_endpoints"),
        propose("export_records", to="x", amount=1),
        propose("disable_logging"),
        propose("unknown_tool"),
    ):
        assert service.handle(proposal, session).decision.rule_id


# --- audit trail --------------------------------------------------------------------------


def test_each_handled_call_is_audited(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    service, _state, session = build_service(tmp_path)
    before = audit_path.read_text(encoding="utf-8").count("\n")
    service.handle(propose("list_endpoints"), session)
    after = audit_path.read_text(encoding="utf-8").count("\n")
    assert after == before + 1  # exactly one DecisionEvent appended
