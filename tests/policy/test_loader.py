"""Fail-closed YAML policy loader (issue #6 / T2.3).

Covers: a real policies/rmm.yaml loads and validates; unknown fields, invalid enums,
malformed YAML, missing files, and unregistered predicate names all raise PolicyError.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.monitor.types import CallId, Principal, SequenceState, SessionId, ToolCall
from src.monitor.verdict import evaluate
from src.policy.loader import PolicyError, load_policy, validate_policy
from src.transport.contract import Verdict

REPO_ROOT = Path(__file__).resolve().parents[2]
RMM = REPO_ROOT / "policies" / "rmm.yaml"


def make_call(tool: str) -> ToolCall:
    return ToolCall(
        tool=tool,
        args={},
        session_id=SessionId("s1"),
        principal=Principal("client-1"),
        call_id=CallId("c1"),
        timestamp=0.0,
    )


def test_rmm_policy_loads_and_validates() -> None:
    policy = load_policy(RMM)
    tools = {r.tool for r in policy.rules}
    assert {"list_endpoints", "list_shares", "register_destination", "export_records"} <= tools


def test_rmm_policy_allows_read_and_gates_transfer() -> None:
    policy = load_policy(RMM)
    state = SequenceState()
    assert evaluate(make_call("list_endpoints"), policy, state).verdict is Verdict.ALLOW
    assert evaluate(make_call("export_records"), policy, state).verdict is Verdict.GATE


def test_unmatched_tool_falls_through_to_default_deny() -> None:
    policy = load_policy(RMM)
    d = evaluate(make_call("wire_to_offshore"), policy, SequenceState())
    assert d.verdict is Verdict.DENY
    assert d.rule_id == "default"


def test_validate_rejects_unknown_top_level_field() -> None:
    with pytest.raises(PolicyError):
        validate_policy({"rules": [], "bogus": 1})


def test_validate_rejects_unknown_rule_field() -> None:
    bad = {
        "rules": [{"rule_id": "x", "tool": "t", "trigger": "action", "enforce": "allow", "oops": 1}]
    }
    with pytest.raises(PolicyError):
        validate_policy(bad)


def test_validate_rejects_invalid_enforce_value() -> None:
    bad = {"rules": [{"rule_id": "x", "tool": "t", "trigger": "action", "enforce": "maybe"}]}
    with pytest.raises(PolicyError):
        validate_policy(bad)


def test_validate_rejects_unregistered_predicate() -> None:
    bad = {
        "rules": [
            {
                "rule_id": "x",
                "tool": "t",
                "trigger": "action",
                "enforce": "allow",
                "checks": [{"predicate": "not_a_real_predicate"}],
            }
        ]
    }
    with pytest.raises(PolicyError):
        validate_policy(bad)


def test_validate_accepts_empty_sequence_block() -> None:
    # Sequence parsing landed in #12; an empty chains list is a valid, empty SequenceConfig.
    policy = validate_policy({"rules": [], "sequence": {"chains": []}})
    assert policy.sequence.chains == ()


def chain_policy(steps: list[dict[str, object]], name: str = "c") -> dict[str, object]:
    """A minimal policy carrying one modeled chain, for structural validation tests."""
    return {"rules": [], "sequence": {"chains": [{"name": name, "domain": "rmm", "steps": steps}]}}


def test_validate_rejects_disconnected_chain_steps() -> None:
    # A step whose `from` is not the previous step's `to` is unreachable at runtime; reject at
    # load time rather than shipping a chain that silently never fires.
    raw = chain_policy(
        [
            {"trigger": "list_endpoints", "to": "S1_ENDPOINTS"},
            {"trigger": "list_shares", "from": "WRONG", "to": "S2_SHARES"},
        ],
        name="broken",
    )
    with pytest.raises(PolicyError, match="previous step's to node"):
        validate_policy(raw)


def test_validate_rejects_sequence_allow() -> None:
    # The sequence layer may only tighten (sequence-engine.md §8): a chain that could emit ALLOW
    # would let a modeled composition loosen per-call policy.
    raw = chain_policy(
        [
            {
                "trigger": "export_records",
                "to": "DONE",
                "enforce": "allow",
                "rule_id": "bad.allow",
            }
        ],
        name="loosens_policy",
    )
    with pytest.raises(PolicyError, match="may only tighten"):
        validate_policy(raw)


def test_validate_rejects_non_argument_binding_source() -> None:
    # Bindings capture monitor-owned call arguments only. Anything else would let policy bind a
    # value the agent controls the meaning of.
    raw = chain_policy(
        [
            {
                "trigger": "register_destination",
                "to": "S1",
                "bind": {"destination": "agent.claimed_destination"},
            }
        ],
        name="bad_binding",
    )
    with pytest.raises(PolicyError, match=r"args\.<name>"):
        validate_policy(raw)


def test_load_missing_file_raises_policy_error() -> None:
    with pytest.raises(PolicyError):
        load_policy(REPO_ROOT / "policies" / "does_not_exist.yaml")


def test_load_malformed_yaml_raises_policy_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules: [unterminated", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(bad)
