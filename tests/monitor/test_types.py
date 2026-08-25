"""Core value-type contracts (issue #5 / T2.2).

Covers the frozen `Decision`, its mandatory traceable `rule_id`, and the pure
`SequenceState.for_subject` accessor.
"""

from __future__ import annotations

import dataclasses

import pytest

from src.monitor.types import (
    ChainProgress,
    Decision,
    Principal,
    SequenceState,
    SessionId,
    SubjectKey,
)
from src.transport.contract import Verdict


def test_decision_is_frozen() -> None:
    d = Decision(verdict=Verdict.DENY, rule_id="default", reason="x")
    with pytest.raises(dataclasses.FrozenInstanceError):
        d.verdict = Verdict.ALLOW  # type: ignore[misc]


def test_decision_requires_non_empty_rule_id() -> None:
    with pytest.raises(ValueError):
        Decision(verdict=Verdict.DENY, rule_id="", reason="no rule id")


def test_for_subject_returns_empty_tuple_for_unknown_subject() -> None:
    state = SequenceState()
    key = SubjectKey(session_id=SessionId("s1"), principal=Principal("p1"))
    assert state.for_subject(key) == ()


def test_for_subject_returns_stored_progress() -> None:
    key = SubjectKey(session_id=SessionId("s1"), principal=Principal("p1"))
    progress = (ChainProgress(chain="recon_add_drain", node="n1"),)
    state = SequenceState(progress={key: progress})
    assert state.for_subject(key) == progress
