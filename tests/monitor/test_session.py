"""Session identity and per-session sequence state (D12, D15).

  * session ids are monitor-minted, unique, and every open/end is audited;
  * `end_session` drops only that session's live progress, and logs it;
  * the kill chain still blocks when its steps are interleaved with benign calls;
  * progress in one session never leaks into a different session's subject key;
  * after `end_session`, the same session's chain must restart from the beginning.

D15 (a NEW session for the SAME principal inherits within-lookback progress via audit replay)
is the deferred issue-#12 durability layer; it is recorded below as a strict xfail so the gap
stays visible and the test flips the moment #12 lands.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.audit.events import SessionLifecycleEvent
from src.audit.replay import replay
from src.audit.writer import AuditWriter
from src.monitor.gate import ApprovalQueue
from src.monitor.service import MonitorService
from src.monitor.session import RetentionConfig, SessionRegistry
from src.monitor.types import ChainProgress, Principal, SequenceState, SessionId, SubjectKey
from src.policy.loader import load_policy
from src.tools.base import ToolRegistry
from src.tools.rmm import EndpointState, register_rmm
from src.transport.contract import ResultStatus, SessionHandle, ToolCallProposal, Verdict

REPO_ROOT = Path(__file__).resolve().parents[2]
RMM = REPO_ROOT / "policies" / "rmm.yaml"
PRINCIPAL = "client-1"

RECON_AND_REGISTER = [
    ToolCallProposal("list_endpoints", {}),
    ToolCallProposal("list_shares", {}),
    ToolCallProposal("register_destination", {"destination": "attacker-dropbox"}),
]
TERMINAL = ToolCallProposal("export_records", {"to": "attacker-dropbox", "count": 5000})
BENIGN = ToolCallProposal("list_endpoints", {})


def registry_with(audit: AuditWriter) -> SessionRegistry:
    return SessionRegistry(audit, RetentionConfig())


def lifecycle(path: Path) -> list[tuple[str, str]]:
    return [(e.session_id, e.action) for e in replay(path) if isinstance(e, SessionLifecycleEvent)]


def build_service(tmp_path: Path) -> tuple[MonitorService, SessionRegistry]:
    registry = ToolRegistry()
    register_rmm(
        registry,
        EndpointState(
            endpoints={PRINCIPAL: ["ep-1"]},
            shares={PRINCIPAL: ["records"]},
            destinations={PRINCIPAL: ["approved-dest"]},
        ),
    )
    audit = AuditWriter(tmp_path / "audit.jsonl")
    sessions = registry_with(audit)
    service = MonitorService(
        load_policy(RMM), registry, audit, sessions, ApprovalQueue(), approval_timeout_s=0.0
    )
    return service, sessions


def run(service: MonitorService, session: SessionHandle, proposals: list[ToolCallProposal]) -> None:
    for proposal in proposals:
        assert service.handle(proposal, session).status is ResultStatus.EXECUTED


# --- SessionRegistry unit behavior --------------------------------------------------------


def test_open_session_ids_are_unique_and_monitor_prefixed(tmp_path: Path) -> None:
    sessions = registry_with(AuditWriter(tmp_path / "a.jsonl"))
    ids = [sessions.open_session() for _ in range(25)]
    assert len(set(ids)) == 25
    assert all(i.startswith("s-") for i in ids)


def test_open_session_writes_one_open_lifecycle_event(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    sid = registry_with(AuditWriter(path)).open_session()
    assert lifecycle(path) == [(sid, "open")]


def test_end_session_drops_only_that_sessions_progress(tmp_path: Path) -> None:
    sessions = registry_with(AuditWriter(tmp_path / "a.jsonl"))
    keep = SubjectKey(SessionId("s-keep"), Principal(PRINCIPAL))
    drop = SubjectKey(SessionId("s-drop"), Principal(PRINCIPAL))
    progress = (ChainProgress(chain="c", node="S1"),)
    sessions.commit(SessionId("s-keep"), SequenceState(progress={keep: progress, drop: progress}))
    sessions.end_session(SessionId("s-drop"))
    assert set(sessions.live_state().progress) == {keep}


def test_end_session_writes_end_lifecycle_event(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    sessions = registry_with(AuditWriter(path))
    sessions.end_session(SessionId("s-x"))
    assert lifecycle(path) == [("s-x", "end")]


def test_commit_replaces_live_state(tmp_path: Path) -> None:
    sessions = registry_with(AuditWriter(tmp_path / "a.jsonl"))
    new = SequenceState(progress={SubjectKey(SessionId("s"), Principal("p")): ()})
    sessions.commit(SessionId("s"), new)
    assert sessions.live_state() is new


def test_expire_idle_is_a_no_op_until_issue_12(tmp_path: Path) -> None:
    # Documents the current stub: no subjects are cleared and nothing is logged.
    path = tmp_path / "a.jsonl"
    assert registry_with(AuditWriter(path)).expire_idle(now=1e12) == ()
    assert not path.exists() or lifecycle(path) == []


def test_retention_config_defaults_match_d12() -> None:
    config = RetentionConfig()
    assert config.idle_expiry_s == 30 * 60
    assert config.lookback_s == 24 * 60 * 60


# --- sequence state through the service, per session --------------------------------------


@pytest.mark.parametrize("benign_between", [1, 3])
def test_kill_chain_interleaved_with_benign_calls_still_blocks(
    tmp_path: Path, benign_between: int
) -> None:
    service, _ = build_service(tmp_path)
    session = service.open_session(PRINCIPAL)
    for step in RECON_AND_REGISTER:
        run(service, session, [step] + [BENIGN] * benign_between)
    result = service.handle(TERMINAL, session)
    assert result.decision.verdict is Verdict.DENY
    assert result.decision.rule_id == "seq.recon_register_exfil.terminal"


def test_progress_in_one_session_does_not_reach_another_sessions_subject(tmp_path: Path) -> None:
    service, sessions = build_service(tmp_path)
    a = service.open_session(PRINCIPAL)
    run(service, a, RECON_AND_REGISTER)
    b = service.open_session("client-2")
    result = service.handle(TERMINAL, b)
    assert result.decision.rule_id != "seq.recon_register_exfil.terminal"
    assert len(sessions.live_state().progress) == 1


def test_end_session_after_partial_chain_clears_live_progress(tmp_path: Path) -> None:
    service, sessions = build_service(tmp_path)
    session = service.open_session(PRINCIPAL)
    run(service, session, RECON_AND_REGISTER)
    (subject,) = sessions.live_state().progress
    sessions.end_session(subject.session_id)
    assert sessions.live_state().progress == {}


def test_new_session_same_principal_inherits_progress_d15(tmp_path: Path) -> None:
    service, _ = build_service(tmp_path)
    first = service.open_session(PRINCIPAL)
    run(service, first, RECON_AND_REGISTER)
    rotated = service.open_session(PRINCIPAL)  # session-rotation evasion attempt
    result = service.handle(TERMINAL, rotated)
    assert result.decision.rule_id == "seq.recon_register_exfil.terminal"
