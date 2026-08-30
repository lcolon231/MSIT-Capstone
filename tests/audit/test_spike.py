"""Offline DENY/GATE spike analyzer over the audit log (issue #58).

The analyzer is a *detection aid*, never part of a `Decision`. It tallies DENY and GATE
verdicts per session and flags sessions whose burst meets a configurable threshold — the
classic prompt-injection tell (a spike of denials / approval-requests from one session).
"""

from __future__ import annotations

from pathlib import Path

from src.audit.spike import SessionCounts, flag_spikes, tally
from src.audit.writer import AuditWriter
from src.monitor.types import Principal, SessionId
from src.transport.contract import Verdict
from tests.audit.samples import decision_ev, lifecycle_ev


def test_tally_counts_deny_and_gate_per_session() -> None:
    events = [
        decision_ev(session_id=SessionId("s1"), verdict=Verdict.DENY),
        decision_ev(session_id=SessionId("s1"), verdict=Verdict.GATE),
        decision_ev(session_id=SessionId("s1"), verdict=Verdict.ALLOW),
        decision_ev(session_id=SessionId("s2"), verdict=Verdict.DENY),
    ]
    counts = tally(events)
    assert counts[SessionId("s1")].deny == 1
    assert counts[SessionId("s1")].gate == 1
    assert counts[SessionId("s1")].total == 3
    assert counts[SessionId("s2")].deny == 1
    assert counts[SessionId("s2")].gate == 0


def test_tally_ignores_non_decision_events() -> None:
    events = [lifecycle_ev(), decision_ev(session_id=SessionId("s1"), verdict=Verdict.DENY)]
    counts = tally(events)
    assert set(counts) == {SessionId("s1")}
    assert counts[SessionId("s1")].deny == 1


def test_session_counts_captures_principal_and_time_span() -> None:
    events = [
        decision_ev(session_id=SessionId("s1"), verdict=Verdict.DENY, timestamp=10.0),
        decision_ev(session_id=SessionId("s1"), verdict=Verdict.DENY, timestamp=15.0),
    ]
    counts = tally(events)[SessionId("s1")]
    assert counts.principal == Principal("client-1")
    assert counts.first_ts == 10.0
    assert counts.last_ts == 15.0


def test_flagged_true_when_deny_meets_threshold() -> None:
    c = SessionCounts(SessionId("s1"), Principal("p"), deny=3, gate=0, total=3,
                      first_ts=0.0, last_ts=1.0)
    assert c.flagged(deny_threshold=3, gate_threshold=99)


def test_flagged_true_when_gate_meets_threshold() -> None:
    c = SessionCounts(SessionId("s1"), Principal("p"), deny=0, gate=5, total=5,
                      first_ts=0.0, last_ts=1.0)
    assert c.flagged(deny_threshold=99, gate_threshold=5)


def test_flagged_false_below_both_thresholds() -> None:
    c = SessionCounts(SessionId("s1"), Principal("p"), deny=2, gate=2, total=10,
                      first_ts=0.0, last_ts=1.0)
    assert not c.flagged(deny_threshold=3, gate_threshold=3)


def test_flag_spikes_reads_log_and_flags_only_over_threshold(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    # noisy session: 3 denials -> flagged
    for _ in range(3):
        writer.append(decision_ev(session_id=SessionId("noisy"), verdict=Verdict.DENY))
    # quiet session: 1 denial -> not flagged
    writer.append(decision_ev(session_id=SessionId("quiet"), verdict=Verdict.DENY))

    flagged = flag_spikes(path, deny_threshold=3, gate_threshold=3)

    assert [c.session_id for c in flagged] == [SessionId("noisy")]
    assert flagged[0].deny == 3


def test_flag_spikes_returns_empty_when_all_quiet(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    writer.append(decision_ev(session_id=SessionId("s1"), verdict=Verdict.ALLOW))
    writer.append(decision_ev(session_id=SessionId("s1"), verdict=Verdict.DENY))
    assert flag_spikes(path, deny_threshold=3, gate_threshold=3) == []


def test_flag_spikes_orders_by_severity(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    for _ in range(3):
        writer.append(decision_ev(session_id=SessionId("mild"), verdict=Verdict.GATE))
    for _ in range(9):
        writer.append(decision_ev(session_id=SessionId("severe"), verdict=Verdict.DENY))

    flagged = flag_spikes(path, deny_threshold=3, gate_threshold=3)

    assert [c.session_id for c in flagged] == [SessionId("severe"), SessionId("mild")]
