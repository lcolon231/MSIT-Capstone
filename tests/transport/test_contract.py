"""Neutral transport contract and wire codec (D11, interface-contracts.md §3, §4.1).

* the DTOs carry no identity/verdict fields and are immutable;
* proposal and result round-trip losslessly through the JSON wire form;
* `proposal_from_wire` never raises on a bad shape — it normalizes to a call the monitor
  rejects (empty tool → unknown-tool DENY), so a garbage body can never crash the server open;
* `result_from_wire` rejects an undecodable response instead of inventing a verdict.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from src.transport.contract import (
    DecisionSummary,
    ResultStatus,
    SessionHandle,
    ToolCallProposal,
    ToolResult,
    Verdict,
    proposal_from_wire,
    proposal_to_wire,
    result_from_wire,
    result_to_wire,
)


def test_tool_call_proposal_has_only_tool_and_args_fields() -> None:
    assert [f.name for f in dataclasses.fields(ToolCallProposal)] == ["tool", "args"]


def test_tool_call_proposal_is_frozen() -> None:
    proposal = ToolCallProposal("t", {})
    with pytest.raises(dataclasses.FrozenInstanceError):
        proposal.tool = "other"  # type: ignore[misc]


def test_session_handle_is_frozen() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        SessionHandle("tok").token = "forged"  # type: ignore[misc]


def test_verdict_has_exactly_allow_deny_gate() -> None:
    assert {member.value for member in Verdict} == {"allow", "deny", "gate"}


def test_result_status_matches_interface_contract() -> None:
    # interface-contracts.md §3: pending approval stays monitor-internal; never a status.
    assert {m.value for m in ResultStatus} == {"executed", "tool_failed", "denied"}


@pytest.mark.parametrize(
    "args",
    [{}, {"to": "x", "count": 5}, {"nested": {"a": [1, 2, {"b": None}]}}, {"unicode": "мир"}],
)
def test_proposal_wire_round_trip_is_lossless(args: dict[str, object]) -> None:
    proposal = ToolCallProposal("export_records", args)
    wire = json.loads(json.dumps(proposal_to_wire(proposal)))
    assert proposal_from_wire(wire) == proposal


@pytest.mark.parametrize(
    "data",
    [None, [], "string", 42, {}, {"args": {}}, {"tool": None}],
    ids=["none", "list", "str", "int", "empty", "no-tool", "null-tool"],
)
def test_proposal_from_wire_bad_shape_normalizes_without_raising(data: object) -> None:
    proposal = proposal_from_wire(data)
    assert isinstance(proposal, ToolCallProposal)
    assert proposal.args == {}


@pytest.mark.parametrize("bad_args", [None, [], "a=1", 3, [["k", "v"]]])
def test_proposal_from_wire_non_mapping_args_become_empty(bad_args: object) -> None:
    assert proposal_from_wire({"tool": "t", "args": bad_args}).args == {}


def test_proposal_from_wire_non_mapping_body_yields_empty_tool() -> None:
    assert proposal_from_wire(["list_endpoints"]).tool == ""


@pytest.mark.parametrize("status", list(ResultStatus))
@pytest.mark.parametrize("verdict", list(Verdict))
def test_result_wire_round_trip_is_lossless(status: ResultStatus, verdict: Verdict) -> None:
    result = ToolResult(status, DecisionSummary(verdict, "rule.x", "why"), {"k": [1, 2]})
    wire = json.loads(json.dumps(result_to_wire(result)))
    assert result_from_wire(wire) == result


def test_result_from_wire_missing_payload_defaults_to_none() -> None:
    wire = {"status": "denied", "decision": {"verdict": "deny", "rule_id": "r", "reason": "x"}}
    assert result_from_wire(wire).payload is None


@pytest.mark.parametrize(
    "wire",
    [
        {},
        {"status": "denied"},
        {"status": "executed", "decision": {"verdict": "maybe", "rule_id": "r", "reason": ""}},
        {"status": "weird", "decision": {"verdict": "allow", "rule_id": "r", "reason": ""}},
        {"status": "executed", "decision": {"verdict": "allow", "reason": ""}},
    ],
    ids=["empty", "no-decision", "bad-verdict", "bad-status", "no-rule-id"],
)
def test_result_from_wire_undecodable_raises_instead_of_inventing_a_verdict(
    wire: dict[str, object],
) -> None:
    with pytest.raises((KeyError, ValueError)):
        result_from_wire(wire)
