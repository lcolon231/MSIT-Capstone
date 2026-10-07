"""D15 — a new session inherits its principal's recent chain progress via audit replay.

`reconstruct_sequence_state` (pure over the log):
  * folds ChainProgressEvents for ONE principal, from any session, within the lookback window,
    and keys the result to the new session;
  * never regresses: a later event at a shallower node (another session redoing recon) cannot
    undo deeper progress; at equal depth the newer binding wins;
  * ignores other principals, out-of-window events, and nodes/chains the policy no longer has;
  * applies evictions; does NOT treat session end as a barrier; raises on a corrupt record.

`SessionRegistry.state_for` seeds a cold subject once, and the service turns a corrupt history
into a DENY. Every timestamp comes from an injected clock — no wall-clock waits.
"""

from __future__ import annotations

import types
from pathlib import Path

import pytest

import src.monitor.service as service_mod
from src.audit.events import (
    AuditFormatError,
    ChainProgressEvent,
    EvictionEvent,
    SessionLifecycleEvent,
)
from src.audit.replay import reconstruct_sequence_state
from src.audit.writer import AuditWriter
from src.monitor.gate import ApprovalQueue
from src.monitor.sequence import _canonical_digest, node_ranks
from src.monitor.service import MonitorService
from src.monitor.session import RetentionConfig, SessionRegistry
from src.monitor.types import Principal, SessionId, SubjectKey
from src.policy.loader import load_policy
from src.tools.base import ToolRegistry
from src.tools.rmm import EndpointState, register_rmm
from src.transport.contract import SessionHandle, ToolCallProposal, Verdict

REPO_ROOT = Path(__file__).resolve().parents[2]
RMM = REPO_ROOT / "policies" / "rmm.yaml"
CHAIN = "recon_register_exfil"
P = Principal("client-1")
NEW = SessionId("s-new")
DAY = 24 * 60 * 60
T0 = 1_000_000.0
RANKS = node_ranks(load_policy(RMM))


class Clock:
    def __init__(self, now: float = T0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def progress(
    to: str,
    t: float,
    *,
    session: str = "s-old",
    principal: str = "client-1",
    chain: str = CHAIN,
    frm: str = "x",
    bindings: dict[str, str] | None = None,
) -> ChainProgressEvent:
    return ChainProgressEvent(
        session_id=SessionId(session),
        principal=Principal(principal),
        chain=chain,
        from_node=frm,
        to_node=to,
        bindings=bindings or {},
        timestamp=t,
    )


def log(tmp_path: Path, *events: object) -> Path:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    for event in events:
        writer.append(event)  # type: ignore[arg-type]
    return path


def seed(path: Path, now: float = T0 + 10, lookback: float = DAY) -> list[tuple[str, dict]]:
    state = reconstruct_sequence_state(path, P, NEW, now, lookback, RANKS)
    return [(c.node, dict(c.bindings)) for c in state.for_subject(SubjectKey(NEW, P))]


DEST = {"registered_destination": _canonical_digest("attacker-dropbox")}


# --- reconstruct_sequence_state -----------------------------------------------------------


def test_reconstruct_missing_log_is_empty(tmp_path: Path) -> None:
    assert seed(tmp_path / "absent.jsonl") == []


def test_reconstruct_folds_principal_history_and_rekeys_to_new_session(tmp_path: Path) -> None:
    path = log(
        tmp_path,
        progress("S1_ENDPOINTS", T0),
        progress("S2_SHARES", T0 + 1),
        progress("S3_DESTINATION_ADDED", T0 + 2, bindings=DEST),
    )
    state = reconstruct_sequence_state(path, P, NEW, T0 + 10, DAY, RANKS)
    assert list(state.progress) == [SubjectKey(NEW, P)]
    (chain,) = state.for_subject(SubjectKey(NEW, P))
    assert (chain.node, dict(chain.bindings)) == ("S3_DESTINATION_ADDED", DEST)
    assert chain.updated_at == T0 + 2
    assert set(chain.step_times) == {"S1_ENDPOINTS", "S2_SHARES", "S3_DESTINATION_ADDED"}


def test_reconstruct_merges_progress_made_across_several_old_sessions(tmp_path: Path) -> None:
    path = log(
        tmp_path,
        progress("S1_ENDPOINTS", T0, session="s-a"),
        progress("S2_SHARES", T0 + 1, session="s-b"),
        progress("S3_DESTINATION_ADDED", T0 + 2, session="s-c", bindings=DEST),
    )
    assert seed(path) == [("S3_DESTINATION_ADDED", DEST)]


def test_reconstruct_later_shallower_event_does_not_regress(tmp_path: Path) -> None:
    path = log(
        tmp_path,
        progress("S3_DESTINATION_ADDED", T0, session="s-a", bindings=DEST),
        progress("S1_ENDPOINTS", T0 + 5, session="s-b"),  # concurrent session redoing recon
    )
    assert seed(path) == [("S3_DESTINATION_ADDED", DEST)]


def test_reconstruct_equal_depth_takes_newest_binding(tmp_path: Path) -> None:
    newer = {"registered_destination": _canonical_digest("second")}
    path = log(
        tmp_path,
        progress("S3_DESTINATION_ADDED", T0, bindings=DEST),
        progress("S3_DESTINATION_ADDED", T0 + 1, bindings=newer),
    )
    assert seed(path) == [("S3_DESTINATION_ADDED", newer)]


def test_reconstruct_ignores_other_principals(tmp_path: Path) -> None:
    path = log(tmp_path, progress("S2_SHARES", T0, principal="client-2"))
    assert seed(path) == []


@pytest.mark.parametrize(
    "timestamp", [T0 + 10 - DAY - 1, T0 + 11], ids=["older-than-lookback", "in-the-future"]
)
def test_reconstruct_ignores_events_outside_window(tmp_path: Path, timestamp: float) -> None:
    assert seed(log(tmp_path, progress("S2_SHARES", timestamp))) == []


def test_reconstruct_includes_event_exactly_at_window_edge(tmp_path: Path) -> None:
    assert seed(log(tmp_path, progress("S1_ENDPOINTS", T0 + 10 - DAY))) == [("S1_ENDPOINTS", {})]


@pytest.mark.parametrize(
    ("chain", "node"), [("retired_chain", "S1"), (CHAIN, "S9_REMOVED")], ids=["chain", "node"]
)
def test_reconstruct_ignores_progress_the_policy_no_longer_models(
    tmp_path: Path, chain: str, node: str
) -> None:
    assert seed(log(tmp_path, progress(node, T0, chain=chain))) == []


def test_reconstruct_eviction_at_current_node_drops_chain(tmp_path: Path) -> None:
    eviction = EvictionEvent(
        session_id=SessionId("s-old"),
        principal=P,
        chain=CHAIN,
        evicted_node="S2_SHARES",
        reason="cap",
        timestamp=T0 + 1,
    )
    assert seed(log(tmp_path, progress("S2_SHARES", T0), eviction)) == []


def test_reconstruct_eviction_of_a_stale_node_is_ignored(tmp_path: Path) -> None:
    eviction = EvictionEvent(
        session_id=SessionId("s-old"),
        principal=P,
        chain=CHAIN,
        evicted_node="S1_ENDPOINTS",
        reason="cap",
        timestamp=T0 + 2,
    )
    path = log(tmp_path, progress("S1_ENDPOINTS", T0), progress("S2_SHARES", T0 + 1), eviction)
    assert seed(path) == [("S2_SHARES", {})]


def test_reconstruct_session_end_is_not_a_replay_barrier(tmp_path: Path) -> None:
    end = SessionLifecycleEvent(
        session_id=SessionId("s-old"), principal=None, action="end", timestamp=T0 + 1
    )
    assert seed(log(tmp_path, progress("S2_SHARES", T0), end)) == [("S2_SHARES", {})]


def test_reconstruct_corrupt_record_raises(tmp_path: Path) -> None:
    path = log(tmp_path, progress("S1_ENDPOINTS", T0))
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"type": "chain_progress", "garbage": true}\n')
    with pytest.raises(AuditFormatError):
        seed(path)


def test_node_ranks_follow_chain_step_order() -> None:
    assert RANKS[CHAIN] == {
        "S1_ENDPOINTS": 1,
        "S2_SHARES": 2,
        "S3_DESTINATION_ADDED": 3,
        "S4_BLOCKED": 4,
    }


# --- SessionRegistry.state_for ------------------------------------------------------------


def registry(path: Path, clock: Clock) -> SessionRegistry:
    return SessionRegistry(AuditWriter(path), RetentionConfig(), clock=clock)


def test_state_for_seeds_cold_subject_from_history(tmp_path: Path) -> None:
    path = log(tmp_path, progress("S2_SHARES", T0))
    state = registry(path, Clock(T0 + 1)).state_for(NEW, P, RANKS)
    assert [c.node for c in state.for_subject(SubjectKey(NEW, P))] == ["S2_SHARES"]


def test_state_for_without_ranks_does_not_seed(tmp_path: Path) -> None:
    path = log(tmp_path, progress("S2_SHARES", T0))
    assert registry(path, Clock(T0 + 1)).state_for(NEW, P).progress == {}


def test_state_for_seeds_only_once_per_subject(tmp_path: Path) -> None:
    path = log(tmp_path, progress("S1_ENDPOINTS", T0))
    sessions = registry(path, Clock(T0 + 1))
    sessions.state_for(NEW, P, RANKS)
    AuditWriter(path).append(progress("S2_SHARES", T0 + 0.5))  # arrives after seeding
    state = sessions.state_for(NEW, P, RANKS)
    assert [c.node for c in state.for_subject(SubjectKey(NEW, P))] == ["S1_ENDPOINTS"]


def test_state_for_uses_injected_clock_for_lookback(tmp_path: Path) -> None:
    path = log(tmp_path, progress("S2_SHARES", T0))
    assert registry(path, Clock(T0 + DAY + 1)).state_for(NEW, P, RANKS).progress == {}


def test_state_for_corrupt_log_raises_and_is_retried(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("not json\n", encoding="utf-8")
    sessions = SessionRegistry(AuditWriter(tmp_path / "other.jsonl"), RetentionConfig())
    sessions._audit = types.SimpleNamespace(path=path)  # type: ignore[assignment]
    for _ in range(2):  # not remembered as "seeded" after a failure
        with pytest.raises(AuditFormatError):
            sessions.state_for(NEW, P, RANKS)


# --- end to end through the service -------------------------------------------------------

RECON_AND_REGISTER = [
    ToolCallProposal("list_endpoints", {}),
    ToolCallProposal("list_shares", {}),
    ToolCallProposal("register_destination", {"destination": "attacker-dropbox"}),
]
TERMINAL = ToolCallProposal("export_records", {"to": "attacker-dropbox", "count": 9})


def build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clock: Clock
) -> tuple[MonitorService, SessionRegistry]:
    monkeypatch.setattr(service_mod, "time", types.SimpleNamespace(time=clock))
    registry_ = ToolRegistry()
    register_rmm(
        registry_,
        EndpointState(
            endpoints={P: ["ep"]}, shares={P: ["records"]}, destinations={P: ["approved"]}
        ),
    )
    audit = AuditWriter(tmp_path / "audit.jsonl")
    sessions = SessionRegistry(audit, RetentionConfig(), clock=clock)
    service = MonitorService(load_policy(RMM), registry_, audit, sessions, ApprovalQueue(), 0.0)
    return service, sessions


def run(service: MonitorService, session: SessionHandle) -> None:
    for proposal in RECON_AND_REGISTER:
        service.handle(proposal, session)


def test_rotated_session_still_blocks_the_terminal_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    service, _ = build(tmp_path, monkeypatch, clock)
    run(service, service.open_session(P))
    clock.now += 60
    result = service.handle(TERMINAL, service.open_session(P))
    assert result.decision.rule_id == "seq.recon_register_exfil.terminal"


def test_ended_session_history_still_blocks_a_new_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    service, sessions = build(tmp_path, monkeypatch, clock)
    first = service.open_session(P)
    run(service, first)
    (subject,) = sessions.live_state().progress
    sessions.end_session(subject.session_id)
    result = service.handle(TERMINAL, service.open_session(P))
    assert result.decision.verdict is Verdict.DENY
    assert result.decision.rule_id == "seq.recon_register_exfil.terminal"


def test_history_older_than_lookback_no_longer_blocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    service, _ = build(tmp_path, monkeypatch, clock)
    run(service, service.open_session(P))
    clock.now += DAY + 1
    result = service.handle(TERMINAL, service.open_session(P))
    assert result.decision.rule_id == "rmm.export_records.gate"  # ordinary per-call gate


def test_rotated_session_rerunning_recon_cannot_reset_inherited_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    service, _ = build(tmp_path, monkeypatch, clock)
    run(service, service.open_session(P))
    rotated = service.open_session(P)
    service.handle(ToolCallProposal("list_endpoints", {}), rotated)
    result = service.handle(TERMINAL, rotated)
    assert result.decision.rule_id == "seq.recon_register_exfil.terminal"


def test_corrupt_history_makes_new_session_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    service, _ = build(tmp_path, monkeypatch, clock)
    session = service.open_session(P)
    with (tmp_path / "audit.jsonl").open("a", encoding="utf-8") as handle:
        handle.write("{corrupt\n")
    result = service.handle(ToolCallProposal("list_endpoints", {}), session)
    assert result.decision.verdict is Verdict.DENY
    assert result.decision.rule_id == "system.error"
