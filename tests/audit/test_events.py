"""JSONL (de)serialization of audit events (issue #9 / T2.6)."""

from __future__ import annotations

import json

import pytest

from src.audit.events import AuditEvent, AuditFormatError, from_jsonl, to_jsonl
from src.transport.contract import Verdict
from tests.audit.samples import chain_ev, decision_ev, eviction_ev, lifecycle_ev, tool_exec_ev

SAMPLES = [
    decision_ev(),
    decision_ev(verdict=Verdict.ALLOW, gate_class=None),
    chain_ev(),
    eviction_ev(),
    lifecycle_ev(),
    tool_exec_ev(),
    tool_exec_ev(status="failed", result=None),
]


@pytest.mark.parametrize("event", SAMPLES)
def test_jsonl_round_trip(event: AuditEvent) -> None:
    assert from_jsonl(to_jsonl(event)) == event


def test_to_jsonl_is_single_line() -> None:
    assert "\n" not in to_jsonl(decision_ev())


def test_from_jsonl_rejects_non_json() -> None:
    with pytest.raises(AuditFormatError):
        from_jsonl("{ not json")


def test_from_jsonl_rejects_unknown_type() -> None:
    with pytest.raises(AuditFormatError):
        from_jsonl(json.dumps({"type": "bogus"}))


def test_from_jsonl_rejects_missing_fields() -> None:
    with pytest.raises(AuditFormatError):
        from_jsonl(json.dumps({"type": "decision", "call_id": "c1"}))


@pytest.mark.parametrize(
    "bindings",
    ["cafebabe", ["a"], {"name": 1}, {"name": None}],
    ids=["string", "list", "int-digest", "null-digest"],
)
def test_from_jsonl_rejects_chain_progress_with_malformed_bindings(bindings: object) -> None:
    raw = json.loads(to_jsonl(chain_ev()))
    raw["bindings"] = bindings
    with pytest.raises(AuditFormatError):
        from_jsonl(json.dumps(raw))


def test_chain_progress_bindings_are_named_digests_on_disk() -> None:
    assert json.loads(to_jsonl(chain_ev()))["bindings"] == {"registered_destination": "cafebabe"}


def test_from_jsonl_rejects_tool_execution_with_unknown_status() -> None:
    raw = json.loads(to_jsonl(tool_exec_ev()))
    raw["status"] = "maybe"
    with pytest.raises(AuditFormatError):
        from_jsonl(json.dumps(raw))
