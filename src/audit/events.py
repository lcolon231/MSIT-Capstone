"""Audit event types — the records written to the append-only JSONL log.

Chain-progress, eviction, and session-lifecycle events are FIRST-CLASS records (D12.4/D12.5),
not just decisions, because replay must reconstruct sequence state — and eviction/expiry must
never be silent. Every record carries the fields needed to rebuild the automaton on replay.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from src.monitor.types import GateClass, Principal, SessionId
from src.transport.contract import Verdict


class EventType(Enum):
    DECISION = "decision"
    CHAIN_PROGRESS = "chain_progress"
    EVICTION = "eviction"
    SESSION_LIFECYCLE = "session_lifecycle"


@dataclass(frozen=True)
class DecisionEvent:
    """One verdict. `arg_sha256` is a hash of the call arguments — never plaintext."""

    type: EventType = field(default=EventType.DECISION, init=False)
    call_id: str
    session_id: SessionId
    principal: Principal
    tool: str
    arg_sha256: str
    verdict: Verdict
    rule_id: str  # always non-null (criterion #8, spec.md T8.2)
    reason: str
    gate_class: GateClass | None
    timestamp: float


@dataclass(frozen=True)
class ChainProgressEvent:
    """A sequence-state advance, sufficient to replay the automaton (D12.4)."""

    type: EventType = field(default=EventType.CHAIN_PROGRESS, init=False)
    session_id: SessionId
    principal: Principal
    chain: str
    from_node: str
    to_node: str
    bindings_sha256: str
    timestamp: float


@dataclass(frozen=True)
class EvictionEvent:
    """A least-advanced-first eviction (D12.5) — never silent."""

    type: EventType = field(default=EventType.EVICTION, init=False)
    session_id: SessionId
    principal: Principal
    chain: str
    evicted_node: str
    reason: str
    timestamp: float


@dataclass(frozen=True)
class SessionLifecycleEvent:
    """Session open / end / idle-expiry (D12.3) — logged when it fires."""

    type: EventType = field(default=EventType.SESSION_LIFECYCLE, init=False)
    session_id: SessionId
    principal: Principal | None
    action: str  # "open" | "end" | "idle_expiry"
    timestamp: float


AuditEvent = (
    DecisionEvent | ChainProgressEvent | EvictionEvent | SessionLifecycleEvent
)


def to_jsonl(event: AuditEvent) -> str:
    """Serialize an event to a single JSONL line. Pure."""
    raise NotImplementedError


def from_jsonl(line: str) -> AuditEvent:
    """Parse one JSONL line back into an event (untrusted input — validate shape)."""
    raise NotImplementedError
