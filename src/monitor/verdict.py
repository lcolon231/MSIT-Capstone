"""The pure verdict engine.

`evaluate` is the one function the whole project is organized around. It is a pure function of
`(call, policy, state)` — nothing the agent emits can influence it except by being the call
that is judged (docs/design/architecture.md §1). No I/O, no mutation, no clock, no randomness,
no LLM. Side effects (audit, gate queue, execution, state advance) belong to `service.py`.

Fail-closed composition (spec.md §9):
    1. per-call, argument-aware policy, or the default DENY when no rule matches — the
       baseline verdict for this call considered on its own;
    2. the sequence engine, which may escalate that baseline when a modeled chain reaches a
       blocking transition;
    3. the result is the STRICTER of the two.

Taking the stricter is what makes "the sequence engine only ever tightens"
(docs/design/sequence-engine.md §8) true in code and not merely in prose: a modeled chain can
escalate ALLOW to GATE or DENY, but an escalating chain step can never soften a per-call DENY
into an approvable GATE. A chain that does not fire leaves the per-call verdict untouched.
"""

from __future__ import annotations

from src.monitor import sequence
from src.monitor.types import Decision, SequenceState, ToolCall
from src.policy.schema import Policy
from src.transport.contract import Verdict

# How much each verdict restricts execution. Only the ORDER is meaningful; the numbers are
# comparison keys, not scores, and are never persisted or logged.
_STRICTNESS: dict[Verdict, int] = {
    Verdict.ALLOW: 0,
    Verdict.GATE: 1,
    Verdict.DENY: 2,
}


def evaluate(call: ToolCall, policy: Policy, state: SequenceState) -> Decision:
    """Return the Decision for `call`. Pure and fail-closed.

    A modeled kill chain (sequence.classify) escalates the per-call verdict, so the composition
    can turn a would-be per-call GATE into a DENY — but never the reverse. If nothing matches,
    the default is DENY — never allow (docs/design/sequence-engine.md §2, §8).
    """
    # 1. Per-call, argument-aware policy — the baseline verdict for this call on its own.
    rule = policy.match(call)
    per_call = rule.decide(call) if rule is not None else default_deny()
    # 2. Sequence engine: a modeled chain at a blocking transition escalates that baseline.
    chain_decision = sequence.classify(call, state, policy)
    if chain_decision is None:
        return per_call
    # 3. The chain may only tighten. Ties keep the chain's decision, so a modeled composition
    #    still supplies the traceable chain-scoped rule_id when both layers agree (D16).
    return _stricter_of(chain_decision, per_call)


def _stricter_of(chain: Decision, per_call: Decision) -> Decision:
    """The more restrictive of the two decisions, preferring `chain` on a tie."""
    return chain if _STRICTNESS[chain.verdict] >= _STRICTNESS[per_call.verdict] else per_call


def default_deny() -> Decision:
    """The fail-closed default returned when no rule and no chain matches."""
    return Decision(
        verdict=Verdict.DENY,
        rule_id="default",
        reason="no matching policy (fail-closed)",
    )
