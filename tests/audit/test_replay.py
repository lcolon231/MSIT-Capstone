"""Replay reconstructs a run from the log, and surfaces tampering (issue #9 / T2.6)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.audit.events import AuditFormatError
from src.audit.replay import replay
from src.audit.writer import AuditWriter
from tests.audit.samples import chain_ev, decision_ev, lifecycle_ev


def test_replay_yields_every_event_in_append_order(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    events = [lifecycle_ev(), decision_ev(call_id="a"), chain_ev(), decision_ev(call_id="b")]
    for event in events:
        writer.append(event)
    assert list(replay(path)) == events


def test_replay_reconstructs_every_decision(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    for cid in ("a", "b", "c"):
        writer.append(decision_ev(call_id=cid))
    replayed = [e for e in replay(path) if getattr(e, "call_id", None) in {"a", "b", "c"}]
    assert [e.call_id for e in replayed] == ["a", "b", "c"]  # type: ignore[attr-defined]


def test_replay_detects_midfile_tamper(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    for cid in ("a", "b", "c"):
        writer.append(decision_ev(call_id=cid))
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1] = "corrupted-not-json"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(AuditFormatError):
        list(replay(path))
