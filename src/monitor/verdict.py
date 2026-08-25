"""The pure verdict engine.

`evaluate` is the one function the whole project is organized around. It is a pure function of
`(call, policy, state)` — nothing the agent emits can influence it except by being the call
that is judged (docs/design/architecture.md §1). No I/O, no mutation, no clock, no randomness,
no LLM. Side effects (audit, gate queue, execution, state advance) belong to `service.py`.

Fail-closed order (spec.md §9):
    1. sequence engine first — a modeled chain at a blocking transition wins outright;
    2. per-call, argument-aware policy;
    3. default DENY.
"""

from __future__ import annotations

from src.monitor import sequence
from src.monitor.types import Decision, SequenceState, ToolCall
from src.policy.schema import Policy
from src.transport.contract import Verdict


def evaluate(call: ToolCall, policy: Policy, state: SequenceState) -> Decision:
    """Return the Decision for `call`. Pure and fail-closed.

    A modeled kill chain (sequence.classify) takes precedence over per-call policy, so the
    composition can turn a would-be per-call GATE into a DENY. If nothing matches, the default
    is DENY — never allow (docs/design/sequence-engine.md §2).
    """
    # 1. Sequence engine first: a modeled chain at a blocking transition wins outright.
    chain_decision = sequence.classify(call, state, policy)
    if chain_decision is not None:
        return chain_decision
    # 2. Per-call, argument-aware policy.
    rule = policy.match(call)
    if rule is not None:
        return rule.decide(call)
    # 3. Fail-closed default.
    return default_deny()


def default_deny() -> Decision:
    """The fail-closed default returned when no rule and no chain matches."""
    return Decision(
        verdict=Verdict.DENY,
        rule_id="default",
        reason="no matching policy (fail-closed)",
    )
