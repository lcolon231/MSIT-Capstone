"""Pure verdict engine — fail-closed default (issue #5 / T2.2, spec.md criterion #2).

Scope for #5: the orchestration and the default-DENY path. Real per-call rule matching is
#6/#7; real chain classification is Phase 3. In those tests the policy is `deny_all` (no
rules, no chains), so every call must fall through to the fail-closed default.

The final section covers how the two layers COMBINE: `evaluate` takes the stricter of the
chain and per-call verdicts, so the sequence engine can only ever tighten (§8).
"""

from __future__ import annotations

from src.monitor.sequence import advance
from src.monitor.types import (
    CallId,
    Principal,
    SequenceState,
    SessionId,
    ToolCall,
)
from src.monitor.verdict import default_deny, evaluate
from src.policy.schema import ChainSpec, ChainStep, Policy, Rule, SequenceConfig, TriggerEvent
from src.transport.contract import Verdict


def make_call(tool: str = "list_endpoints", **args: object) -> ToolCall:
    return ToolCall(
        tool=tool,
        args=args,
        session_id=SessionId("s1"),
        principal=Principal("client-1"),
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


# --- the sequence layer may only tighten (sequence-engine.md §8) ---------------------------


def escalating_policy(per_call_rules: tuple[Rule, ...]) -> Policy:
    """A chain whose second step ESCALATES to GATE on `disable_logging`, over the supplied
    per-call rules. Disabling endpoint logging is anti-forensics and is denied outright by
    per-call policy (rmm.disable_logging.deny), so a sequence GATE here would *loosen* it into
    something an operator could approve."""
    chain = ChainSpec(
        name="probe_then_gate",
        domain="rmm",
        steps=(
            ChainStep(trigger="list_endpoints", to_node="P1"),
            ChainStep(
                trigger="disable_logging",
                from_node="P1",
                to_node="P2",
                enforce=Verdict.GATE,
                rule_id="seq.probe.gate",
            ),
        ),
    )
    return Policy(rules=per_call_rules, sequence=SequenceConfig(chains=(chain,)))


def deny_rule(tool: str) -> Rule:
    return Rule(
        rule_id=f"rmm.{tool}.deny",
        tool=tool,
        trigger=TriggerEvent.ACTION,
        checks=(),
        enforce=Verdict.DENY,
    )


def test_sequence_gate_cannot_loosen_a_per_call_deny() -> None:
    policy = escalating_policy((deny_rule("disable_logging"),))
    state = advance(make_call("list_endpoints"), policy, SequenceState())

    decision = evaluate(make_call("disable_logging"), policy, state)

    # The chain reaches an escalating (GATE) transition, but per-call policy DENIES this tool.
    # The stricter verdict must win: the sequence layer only ever tightens.
    assert decision.verdict is Verdict.DENY
    assert decision.rule_id == "rmm.disable_logging.deny"


def test_sequence_gate_cannot_loosen_the_fail_closed_default() -> None:
    # Same escalation, but no per-call rule matches at all, so the baseline is the default DENY.
    policy = escalating_policy(())
    state = advance(make_call("list_endpoints"), policy, SequenceState())

    decision = evaluate(make_call("disable_logging"), policy, state)

    assert decision.verdict is Verdict.DENY
    assert decision.rule_id == "default"


def test_sequence_deny_still_overrides_a_per_call_gate() -> None:
    # Regression guard for the precedence the fix must NOT change: a modeled chain reaching a
    # blocking DENY still wins over a per-call GATE (sequence-engine.md §8, first row).
    chain = ChainSpec(
        name="recon_then_block",
        domain="rmm",
        steps=(
            ChainStep(trigger="list_endpoints", to_node="B1"),
            ChainStep(
                trigger="export_records",
                from_node="B1",
                to_node="B2",
                enforce=Verdict.DENY,
                rule_id="seq.recon_then_block.terminal",
            ),
        ),
    )
    gate_rule = Rule(
        rule_id="rmm.export_records.gate",
        tool="export_records",
        trigger=TriggerEvent.ACTION,
        checks=(),
        enforce=Verdict.GATE,
    )
    policy = Policy(rules=(gate_rule,), sequence=SequenceConfig(chains=(chain,)))
    state = advance(make_call("list_endpoints"), policy, SequenceState())

    decision = evaluate(make_call("export_records"), policy, state)

    assert decision.verdict is Verdict.DENY
    assert decision.rule_id == "seq.recon_then_block.terminal"
