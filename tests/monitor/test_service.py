"""Mediated dispatch — issue #11 / T3.2, complete mediation (criterion #1).

Acceptance:
  * the four banking tools run over in-process state through the service;
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
from src.tools.banking import BankingState, register_banking
from src.tools.base import ToolRegistry
from src.transport.contract import ResultStatus, SessionHandle, ToolCallProposal, Verdict

REPO_ROOT = Path(__file__).resolve().parents[2]
BANKING = REPO_ROOT / "policies" / "banking.yaml"


def build_service(tmp_path: Path, principal: str = "acct-1") -> tuple[MonitorService, BankingState, SessionHandle]:
    state = BankingState(balances={principal: 1000}, payees={principal: ["existing"]})
    registry = ToolRegistry()
    register_banking(registry, state)
    audit = AuditWriter(tmp_path / "audit.jsonl")
    sessions = SessionRegistry(audit, RetentionConfig())
    service = MonitorService(load_policy(BANKING), registry, audit, sessions, ApprovalQueue())
    return service, state, service.open_session(principal)


def propose(tool: str, **args: object) -> ToolCallProposal:
    return ToolCallProposal(tool=tool, args=args)


# --- ALLOW dispatches through to the tool -------------------------------------------------


def test_allowed_call_executes_and_returns_payload(tmp_path: Path) -> None:
    service, _state, session = build_service(tmp_path)
    result = service.handle(propose("get_balance"), session)
    assert result.status is ResultStatus.EXECUTED
    assert result.decision.verdict is Verdict.ALLOW
    assert result.payload == {"principal": "acct-1", "balance": 1000}


def test_allowed_add_payee_mutates_in_process_state(tmp_path: Path) -> None:
    service, state, session = build_service(tmp_path)
    service.handle(propose("add_payee", payee_id="acme"), session)
    assert "acme" in state.payees["acct-1"]


# --- DENY / GATE never execute ------------------------------------------------------------


def test_gate_call_does_not_execute(tmp_path: Path) -> None:
    service, state, session = build_service(tmp_path)
    result = service.handle(propose("transfer_funds", to="acme", amount=200), session)
    assert result.status is ResultStatus.GATED_PENDING
    assert result.decision.verdict is Verdict.GATE
    assert state.balances["acct-1"] == 1000  # not debited — the tool never ran


def test_explicit_deny_rule_blocks(tmp_path: Path) -> None:
    service, _state, session = build_service(tmp_path)
    result = service.handle(propose("delete_transaction_history"), session)
    assert result.status is ResultStatus.DENIED
    assert result.decision.rule_id == "banking.delete_transaction_history.deny"


def test_unknown_tool_is_denied_not_passed_through(tmp_path: Path) -> None:
    service, _state, session = build_service(tmp_path)
    result = service.handle(propose("wire_to_offshore", amount=999), session)
    assert result.status is ResultStatus.DENIED
    assert result.decision.rule_id == "default"  # fail-closed default, no dispatch


# --- complete mediation: never crash open -------------------------------------------------


def test_malformed_args_still_yields_a_decision(tmp_path: Path) -> None:
    service, _state, session = build_service(tmp_path)
    # args is not a mapping — enrichment normalizes to empty and the flow still decides.
    bad = ToolCallProposal(tool="get_balance", args=None)  # type: ignore[arg-type]
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
    result = service.handle(propose("get_balance"), SessionHandle(token="forged"))
    assert result.status is ResultStatus.DENIED
    assert result.decision.rule_id == "system.invalid_session"


def test_every_result_carries_a_non_null_rule_id(tmp_path: Path) -> None:
    service, _state, session = build_service(tmp_path)
    for proposal in (
        propose("get_balance"),
        propose("transfer_funds", to="x", amount=1),
        propose("delete_transaction_history"),
        propose("unknown_tool"),
    ):
        assert service.handle(proposal, session).decision.rule_id


# --- audit trail --------------------------------------------------------------------------


def test_each_handled_call_is_audited(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    service, _state, session = build_service(tmp_path)
    before = audit_path.read_text(encoding="utf-8").count("\n")
    service.handle(propose("get_balance"), session)
    after = audit_path.read_text(encoding="utf-8").count("\n")
    assert after == before + 1  # exactly one DecisionEvent appended
