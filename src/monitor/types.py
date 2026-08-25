"""Core enforcement value types.

PURE LEAF: imports stdlib + `transport.contract` only, never `policy`/`sequence`/`gate`/
`service`/`audit`/`tools`/`agent`. Keeping it a leaf prevents import cycles and lets `policy`
depend on it safely (docs/design/architecture.md §3.4).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, NewType

from src.transport.contract import Verdict

# Monitor-assigned identities. The agent never constructs these.
SessionId = NewType("SessionId", str)
Principal = NewType("Principal", str)  # the account / endpoint / client a chain acts against
CallId = NewType("CallId", str)


class GateClass(Enum):
    """The four irreversible / high-blast-radius classes that route to a human (D5)."""

    FILE_DELETE = "file_delete"
    NETWORK_SEND = "network_send"
    FUND_TRANSFER = "fund_transfer"
    CREDENTIAL_ACCESS = "credential_access"


@dataclass(frozen=True)
class ToolCall:
    """The MONITOR-ENRICHED call. A `ToolCallProposal` plus everything the monitor assigned:
    session, resolved principal, a call id, and a timestamp. `evaluate` and every predicate
    operate on this — never on raw agent input (docs/design/architecture.md §5)."""

    tool: str
    args: Mapping[str, Any]
    session_id: SessionId
    principal: Principal
    call_id: CallId
    timestamp: float  # monitor-side clock (epoch seconds); never agent-supplied


@dataclass(frozen=True)
class Decision:
    """The pure result of `evaluate`. FROZEN, and `rule_id` is ALWAYS non-null and traceable."""

    verdict: Verdict
    rule_id: str
    reason: str
    gate_class: GateClass | None = None  # set only when verdict is GATE

    def __post_init__(self) -> None:
        # Fail-closed hygiene: a Decision without a traceable rule_id is a bug, not a verdict.
        if not self.rule_id:
            raise ValueError("Decision.rule_id must be a non-empty, traceable identifier")


@dataclass(frozen=True)
class SubjectKey:
    """The composite key sequence state is tracked under (D12.1)."""

    session_id: SessionId
    principal: Principal


@dataclass(frozen=True)
class ChainProgress:
    """Progress of one modeled chain for one subject: current automaton node + captured
    bindings + per-step timestamps (docs/design/sequence-engine.md §3)."""

    chain: str
    node: str
    bindings: Mapping[str, Any] = field(default_factory=dict)
    step_times: Mapping[str, float] = field(default_factory=dict)
    updated_at: float = 0.0


@dataclass(frozen=True)
class SequenceState:
    """Immutable snapshot of all chain progress for all subjects. `advance` returns a new
    value; the live mutable copy is owned by `session.py`, not the automaton."""

    progress: Mapping[SubjectKey, tuple[ChainProgress, ...]] = field(default_factory=dict)

    def for_subject(self, key: SubjectKey) -> tuple[ChainProgress, ...]:
        """Return the chain-progress tuple for a subject (empty if none). Pure accessor."""
        return tuple(self.progress.get(key, ()))
