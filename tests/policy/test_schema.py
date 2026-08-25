"""Rule.matches / Rule.decide contracts (issue #6 / T2.3).

Tool-level matching plus fail-closed check evaluation: a rule whose check references a
predicate that is unregistered or not yet implemented must NOT match (fail closed). The
argument-aware predicate *bodies* land in #8; here we only prove the wiring is fail-closed.
"""

from __future__ import annotations

from src.monitor.types import CallId, Principal, SessionId, ToolCall
from src.policy.schema import Check, Rule, TriggerEvent
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


def rule(tool: str, enforce: Verdict, checks: tuple[Check, ...] = ()) -> Rule:
    return Rule(
        rule_id=f"test.{tool}",
        tool=tool,
        trigger=TriggerEvent.ACTION,
        checks=checks,
        enforce=enforce,
    )


def test_matches_true_on_same_tool_no_checks() -> None:
    assert rule("get_balance", Verdict.ALLOW).matches(make_call("get_balance")) is True


def test_matches_false_on_different_tool() -> None:
    assert rule("get_balance", Verdict.ALLOW).matches(make_call("transfer_funds")) is False


def test_matches_fails_closed_when_predicate_unimplemented() -> None:
    # arg_matches is registered but its body is NotImplementedError until #8 -> must not match.
    r = rule("get_balance", Verdict.ALLOW, (Check(predicate="arg_matches", params={}),))
    assert r.matches(make_call("get_balance")) is False


def test_matches_fails_closed_on_unknown_predicate() -> None:
    r = rule("get_balance", Verdict.ALLOW, (Check(predicate="does_not_exist", params={}),))
    assert r.matches(make_call("get_balance")) is False


def test_decide_returns_enforced_verdict_and_traceable_rule_id() -> None:
    d = rule("transfer_funds", Verdict.GATE).decide(make_call("transfer_funds"))
    assert d.verdict is Verdict.GATE
    assert d.rule_id == "test.transfer_funds"
    assert d.reason
