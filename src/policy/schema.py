"""Policy schema types (D2).

Structure borrows AgentSpec's `trigger / check / enforce` shape (arXiv:2503.18666) as a
declarative *data* form — never Python-callable policy (D2 rejected that: policy-as-code
weakens the auditability/independence claim). `check` entries name vetted predicates from
`predicates.py`; the loader rejects any that are unregistered.

NOTE: the YAML schema is an "ask first" surface (spec.md §10). No `policies/*.yaml` exists
yet, so these types are a PROPOSAL for review, not a change to a committed schema
(docs/design/sequence-engine.md §9).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from src.monitor.types import Decision, ToolCall
from src.policy import predicates
from src.transport.contract import Verdict


class TriggerEvent(Enum):
    """When a rule fires, mirroring AgentSpec's general triggers."""

    ACTION = "action"  # pre-execution, on a proposed tool call
    STATE_CHANGE = "state_change"
    AGENT_FINISH = "agent_finish"


@dataclass(frozen=True)
class Check:
    """A named, vetted predicate reference plus its parameters. Data, not code."""

    predicate: str  # must resolve in predicates.REGISTRY (loader enforces this)
    params: Mapping[str, Any] = field(default_factory=dict)
    negate: bool = False


@dataclass(frozen=True)
class Rule:
    """A per-call, argument-aware rule: fire on `trigger`, if all `checks` pass, `enforce`."""

    rule_id: str
    tool: str  # the tool name this rule matches
    trigger: TriggerEvent
    checks: Sequence[Check]
    enforce: Verdict  # ALLOW / DENY / GATE

    def matches(self, call: ToolCall) -> bool:
        """True iff this rule's tool + checks apply to `call`. Pure and fail-closed."""
        if call.tool != self.tool:
            return False
        return all(_check_holds(check, call) for check in self.checks)

    def decide(self, call: ToolCall) -> Decision:
        """Return this rule's Decision for a matching call. Pure."""
        return Decision(
            verdict=self.enforce,
            rule_id=self.rule_id,
            reason=f"matched rule '{self.rule_id}'",
        )


def _check_holds(check: Check, call: ToolCall) -> bool:
    """Evaluate one check, FAIL-CLOSED: an unregistered or erroring predicate never matches
    (interface-contracts.md §4.5 — exceptions or ambiguity count as a failed match)."""
    try:
        result = predicates.resolve(check.predicate)(call, check.params)
    except Exception:
        return False
    return bool(result) != check.negate


@dataclass(frozen=True)
class ChainStep:
    """One ordered step of a modeled kill chain (docs/design/sequence-engine.md §9)."""

    trigger: str  # tool name that drives this step
    to_node: str
    from_node: str | None = None
    checks: Sequence[Check] = ()
    bind: Mapping[str, str] = field(
        default_factory=dict
    )  # e.g. {"added_payee_id": "args.payee_id"}
    enforce: Verdict | None = None  # set on blocking/escalating steps
    rule_id: str | None = None


@dataclass(frozen=True)
class ChainSpec:
    """A named modeled chain: its domain and its ordered, data-bound steps (D1)."""

    name: str
    domain: str
    steps: Sequence[ChainStep]


@dataclass(frozen=True)
class SequenceConfig:
    """All modeled chains the sequence engine recognizes."""

    chains: Sequence[ChainSpec] = ()


@dataclass(frozen=True)
class Policy:
    """The complete, loaded, validated policy: per-call rules + modeled chains."""

    rules: Sequence[Rule] = ()
    sequence: SequenceConfig = field(default_factory=SequenceConfig)

    def match(self, call: ToolCall) -> Rule | None:
        """First per-call rule that matches `call`, or None. Pure (docs/.../architecture.md §3.5)."""
        for rule in self.rules:
            if rule.matches(call):
                return rule
        return None

    @staticmethod
    def deny_all() -> "Policy":
        """The fail-closed policy returned when loading fails: matches nothing, so every call
        hits the default DENY (docs/design/architecture.md §3.10). Never an empty allow."""
        return Policy(rules=(), sequence=SequenceConfig())
