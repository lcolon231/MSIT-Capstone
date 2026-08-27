"""Fail-closed YAML policy loader (issue #6 / T2.3).

Covers: a real policies/banking.yaml loads and validates; unknown fields, invalid enums,
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
BANKING = REPO_ROOT / "policies" / "banking.yaml"


def make_call(tool: str) -> ToolCall:
    return ToolCall(
        tool=tool,
        args={},
        session_id=SessionId("s1"),
        principal=Principal("acct-1"),
        call_id=CallId("c1"),
        timestamp=0.0,
    )


def test_banking_policy_loads_and_validates() -> None:
    policy = load_policy(BANKING)
    tools = {r.tool for r in policy.rules}
    assert {"get_balance", "list_payees", "add_payee", "transfer_funds"} <= tools


def test_banking_policy_allows_read_and_gates_transfer() -> None:
    policy = load_policy(BANKING)
    state = SequenceState()
    assert evaluate(make_call("get_balance"), policy, state).verdict is Verdict.ALLOW
    assert evaluate(make_call("transfer_funds"), policy, state).verdict is Verdict.GATE


def test_unmatched_tool_falls_through_to_default_deny() -> None:
    policy = load_policy(BANKING)
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


def test_load_missing_file_raises_policy_error() -> None:
    with pytest.raises(PolicyError):
        load_policy(REPO_ROOT / "policies" / "does_not_exist.yaml")


def test_load_malformed_yaml_raises_policy_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules: [unterminated", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(bad)
