"""Per-call verdict engine — criterion #2 (issue #7 / T2.4).

Acceptance for the per-call layer driven through the pure `evaluate`:
  * a matching rule returns its ALLOW / DENY verdict;
  * an unknown tool and any unmatched call fail closed to the default DENY;
  * an empty policy denies everything;
  * every Decision carries a non-null, traceable rule_id.
"""

from __future__ import annotations

from pathlib import Path

from src.monitor.types import CallId, Principal, SequenceState, SessionId, ToolCall
from src.monitor.verdict import evaluate
from src.policy.loader import load_policy
from src.policy.schema import Policy, Rule, SequenceConfig, TriggerEvent
from src.transport.contract import Verdict

REPO_ROOT = Path(__file__).resolve().parents[2]
RMM = REPO_ROOT / "policies" / "rmm.yaml"


def make_call(tool: str, **args: object) -> ToolCall:
    return ToolCall(
        tool=tool,
        args=args,
        session_id=SessionId("s1"),
        principal=Principal("client-1"),
        call_id=CallId("c1"),
        timestamp=0.0,
    )


def rule(rule_id: str, tool: str, enforce: Verdict) -> Rule:
    return Rule(
        rule_id=rule_id,
        tool=tool,
        trigger=TriggerEvent.ACTION,
        checks=(),
        enforce=enforce,
    )


def policy_of(*rules: Rule) -> Policy:
    return Policy(rules=rules, sequence=SequenceConfig())


# --- against the real RMM policy ------------------------------------------------------


def test_matching_allow_rule_allows_with_its_rule_id() -> None:
    d = evaluate(make_call("list_endpoints"), load_policy(RMM), SequenceState())
    assert d.verdict is Verdict.ALLOW
    assert d.rule_id == "rmm.list_endpoints.allow"


def test_matching_deny_rule_denies_with_its_rule_id() -> None:
    # An always-forbidden operation (destroying the audit trail) must be denied by an explicit
    # rule, distinguishable from the fail-closed default by its rule_id.
    d = evaluate(make_call("disable_logging"), load_policy(RMM), SequenceState())
    assert d.verdict is Verdict.DENY
    assert d.rule_id == "rmm.disable_logging.deny"


def test_unknown_tool_fails_closed_to_default() -> None:
    d = evaluate(make_call("wire_to_offshore"), load_policy(RMM), SequenceState())
    assert d.verdict is Verdict.DENY
    assert d.rule_id == "default"
    assert d.reason == "no matching policy (fail-closed)"


# --- against constructed policies (per-call semantics in isolation) -----------------------


def test_constructed_deny_rule_denies() -> None:
    pol = policy_of(rule("x.deny", "danger", Verdict.DENY))
    assert evaluate(make_call("danger"), pol, SequenceState()).verdict is Verdict.DENY


def test_first_matching_rule_wins() -> None:
    deny_first = policy_of(
        rule("x.deny", "t", Verdict.DENY),
        rule("x.allow", "t", Verdict.ALLOW),
    )
    allow_first = policy_of(
        rule("x.allow", "t", Verdict.ALLOW),
        rule("x.deny", "t", Verdict.DENY),
    )
    assert evaluate(make_call("t"), deny_first, SequenceState()).rule_id == "x.deny"
    assert evaluate(make_call("t"), allow_first, SequenceState()).rule_id == "x.allow"


def test_empty_policy_denies_everything() -> None:
    for tool in ("list_endpoints", "export_records", "anything"):
        assert evaluate(make_call(tool), Policy.deny_all(), SequenceState()).verdict is Verdict.DENY


def test_every_verdict_carries_non_null_rule_id() -> None:
    pol = policy_of(
        rule("a", "allow_tool", Verdict.ALLOW),
        rule("d", "deny_tool", Verdict.DENY),
        rule("g", "gate_tool", Verdict.GATE),
    )
    state = SequenceState()
    for tool in ("allow_tool", "deny_tool", "gate_tool", "unmatched_tool"):
        assert evaluate(make_call(tool), pol, state).rule_id
