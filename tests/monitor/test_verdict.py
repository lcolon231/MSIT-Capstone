"""Pure verdict engine — fail-closed default (issue #5 / T2.2, spec.md criterion #2).

Scope for #5: the orchestration and the default-DENY path. Real per-call rule matching is
#6/#7; real chain classification is Phase 3. Here the policy is `deny_all` (no rules, no
chains), so every call must fall through to the fail-closed default.
"""

from __future__ import annotations

from src.monitor.types import (
    CallId,
    Principal,
    SequenceState,
    SessionId,
    ToolCall,
)
from src.monitor.verdict import default_deny, evaluate
from src.policy.schema import Policy
from src.transport.contract import Verdict


def make_call(tool: str = "get_balance", **args: object) -> ToolCall:
    return ToolCall(
        tool=tool,
        args=args,
        session_id=SessionId("s1"),
        principal=Principal("acct-1"),
        call_id=CallId("c1"),
        timestamp=0.0,
    )


def test_default_deny_is_a_traceable_deny() -> None:
    d = default_deny()
    assert d.verdict is Verdict.DENY
    assert d.rule_id == "default"
    assert d.reason


def test_evaluate_fails_closed_with_deny_all_policy() -> None:
    d = evaluate(make_call(), Policy.deny_all(), SequenceState())
    assert d.verdict is Verdict.DENY
    assert d.rule_id == "default"


def test_evaluate_denies_unknown_tool_under_deny_all() -> None:
    d = evaluate(make_call(tool="totally_unknown_tool"), Policy.deny_all(), SequenceState())
    assert d.verdict is Verdict.DENY


def test_evaluate_is_deterministic() -> None:
    call, policy, state = make_call(), Policy.deny_all(), SequenceState()
    assert evaluate(call, policy, state) == evaluate(call, policy, state)


def test_evaluate_does_not_mutate_state_or_policy() -> None:
    state = SequenceState()
    policy = Policy.deny_all()
    evaluate(make_call(), policy, state)
    # Pure: inputs are unchanged (no chains advanced, no rules added).
    assert state.progress == {}
    assert policy.rules == ()
