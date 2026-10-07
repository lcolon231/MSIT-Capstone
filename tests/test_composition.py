"""Monitor composition root (src/composition.py).

* `build_monitor` wires the RMM registry, the given policy, the given audit path, and the
  given approval timeout into one `MonitorService`;
* on ANY policy-load failure the composition root substitutes `Policy.deny_all()` rather than
  crashing — interface-contracts.md §4.5 / architecture.md §3.10. A deny-all monitor is still
  a reference monitor: every call gets a DENY decision and nothing executes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.audit.events import ApprovalResolutionEvent, DecisionEvent
from src.audit.replay import replay
from src.composition import PRINCIPAL, build_monitor
from src.transport.contract import ResultStatus, ToolCallProposal, Verdict

REPO_ROOT = Path(__file__).resolve().parents[1]
RMM = REPO_ROOT / "policies" / "rmm.yaml"

RMM_TOOLS = ["list_endpoints", "list_shares", "register_destination", "export_records"]


def test_build_monitor_allowed_call_executes_against_seeded_principal(tmp_path: Path) -> None:
    service = build_monitor(RMM, tmp_path / "audit.jsonl")
    result = service.handle(ToolCallProposal("list_endpoints", {}), service.open_session())
    assert result.status is ResultStatus.EXECUTED
    assert result.payload == {"endpoints": ["ep-clinic-01", "ep-clinic-02"]}


def test_build_monitor_default_principal_matches_composition_constant(tmp_path: Path) -> None:
    service = build_monitor(RMM, tmp_path / "audit.jsonl")
    service.handle(ToolCallProposal("list_endpoints", {}), service.open_session())
    (event,) = [e for e in replay(tmp_path / "audit.jsonl") if isinstance(e, DecisionEvent)]
    assert event.principal == PRINCIPAL


def test_build_monitor_writes_audit_to_given_path(tmp_path: Path) -> None:
    audit = tmp_path / "nested" / "dir" / "audit.jsonl"
    service = build_monitor(RMM, audit)
    service.handle(ToolCallProposal("list_shares", {}), service.open_session())
    assert any(isinstance(e, DecisionEvent) for e in replay(audit))


def test_build_monitor_passes_approval_timeout_so_unanswered_gate_times_out(
    tmp_path: Path,
) -> None:
    service = build_monitor(RMM, tmp_path / "audit.jsonl", approval_timeout_s=0.0)
    result = service.handle(
        ToolCallProposal("export_records", {"to": "approved-baa-backup", "count": 1}),
        service.open_session(),
    )
    assert result.status is ResultStatus.DENIED
    assert result.decision.verdict is Verdict.GATE
    resolutions = [
        e.resolution
        for e in replay(tmp_path / "audit.jsonl")
        if isinstance(e, ApprovalResolutionEvent)
    ]
    assert resolutions == ["timed_out"]


def test_build_monitor_instances_do_not_share_state(tmp_path: Path) -> None:
    a = build_monitor(RMM, tmp_path / "a.jsonl")
    b = build_monitor(RMM, tmp_path / "b.jsonl")
    session = a.open_session()
    a.handle(ToolCallProposal("register_destination", {"destination": "new-dest"}), session)
    listed = b.handle(ToolCallProposal("list_endpoints", {}), b.open_session())
    assert listed.status is ResultStatus.EXECUTED
    assert not (tmp_path / "b.jsonl").read_text(encoding="utf-8").count("register_destination")


# --- fail-closed policy load: deny-all fallback -------------------------------------------


def _bad_policies(tmp_path: Path) -> dict[str, Path]:
    malformed = tmp_path / "malformed.yaml"
    malformed.write_text("rules: [unclosed", encoding="utf-8")
    unknown_field = tmp_path / "unknown.yaml"
    unknown_field.write_text("rules: []\nbackdoor: allow\n", encoding="utf-8")
    bad_predicate = tmp_path / "pred.yaml"
    bad_predicate.write_text(
        "rules:\n  - {rule_id: r, tool: list_endpoints, trigger: action, enforce: allow,"
        " checks: [{predicate: always_true}]}\n",
        encoding="utf-8",
    )
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    return {
        "missing": tmp_path / "does-not-exist.yaml",
        "directory": tmp_path,
        "malformed": malformed,
        "unknown-field": unknown_field,
        "unregistered-predicate": bad_predicate,
        "empty": empty,
    }


@pytest.mark.parametrize(
    "case",
    ["missing", "directory", "malformed", "unknown-field", "unregistered-predicate", "empty"],
)
@pytest.mark.parametrize("tool", RMM_TOOLS)
def test_build_monitor_bad_policy_falls_back_to_deny_all(
    tmp_path: Path, case: str, tool: str
) -> None:
    policy_path = _bad_policies(tmp_path)[case]
    service = build_monitor(policy_path, tmp_path / "audit.jsonl", approval_timeout_s=0.0)
    result = service.handle(
        ToolCallProposal(tool, {"destination": "d", "to": "d"}), service.open_session()
    )
    assert result.status is ResultStatus.DENIED
    assert result.decision.verdict is Verdict.DENY
    assert result.payload is None


def test_build_monitor_bad_policy_denials_are_still_audited(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    service = build_monitor(tmp_path / "missing.yaml", audit)
    service.handle(ToolCallProposal("list_endpoints", {}), service.open_session())
    decisions = [e for e in replay(audit) if isinstance(e, DecisionEvent)]
    assert [d.verdict for d in decisions] == [Verdict.DENY]


def test_build_monitor_bad_policy_logs_the_deny_all_fallback(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("ERROR", logger="src.composition"):
        build_monitor(tmp_path / "missing.yaml", tmp_path / "audit.jsonl")
    assert any("DENY-ALL" in r.getMessage() for r in caplog.records)


def test_build_monitor_good_policy_logs_nothing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("ERROR", logger="src.composition"):
        build_monitor(RMM, tmp_path / "audit.jsonl")
    assert caplog.records == []
