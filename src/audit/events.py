"""Audit event types — the records written to the append-only JSONL log.

Chain-progress, eviction, and session-lifecycle events are FIRST-CLASS records (D12.4/D12.5),
not just decisions, because replay must reconstruct sequence state — and eviction/expiry must
never be silent. Every record carries the fields needed to rebuild the automaton on replay.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from enum import Enum

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


AuditEvent = DecisionEvent | ChainProgressEvent | EvictionEvent | SessionLifecycleEvent


class AuditFormatError(ValueError):
    """A log line is not a valid, complete audit record. Corrupt records fail closed and are
    never silently skipped (interface-contracts.md §4.7)."""


def _encode(value: object) -> object:
    return value.value if isinstance(value, Enum) else value


def to_jsonl(event: AuditEvent) -> str:
    """Serialize an event to a single JSONL line. Pure."""
    payload = {f.name: _encode(getattr(event, f.name)) for f in dataclasses.fields(event)}
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def from_jsonl(line: str) -> AuditEvent:
    """Parse one JSONL line back into an event (untrusted input — validate shape)."""
    try:
        raw = json.loads(line)
    except json.JSONDecodeError as exc:
        raise AuditFormatError(f"not valid JSON: {exc}") from exc
    if not isinstance(raw, dict) or "type" not in raw:
        raise AuditFormatError("audit record missing 'type'")
    event_type = raw["type"]
    try:
        if event_type == EventType.DECISION.value:
            gate = raw["gate_class"]
            return DecisionEvent(
                call_id=raw["call_id"],
                session_id=SessionId(raw["session_id"]),
                principal=Principal(raw["principal"]),
                tool=raw["tool"],
                arg_sha256=raw["arg_sha256"],
                verdict=Verdict(raw["verdict"]),
                rule_id=raw["rule_id"],
                reason=raw["reason"],
                gate_class=GateClass(gate) if gate is not None else None,
                timestamp=raw["timestamp"],
            )
        if event_type == EventType.CHAIN_PROGRESS.value:
            return ChainProgressEvent(
                session_id=SessionId(raw["session_id"]),
                principal=Principal(raw["principal"]),
                chain=raw["chain"],
                from_node=raw["from_node"],
                to_node=raw["to_node"],
                bindings_sha256=raw["bindings_sha256"],
                timestamp=raw["timestamp"],
            )
        if event_type == EventType.EVICTION.value:
            return EvictionEvent(
                session_id=SessionId(raw["session_id"]),
                principal=Principal(raw["principal"]),
                chain=raw["chain"],
                evicted_node=raw["evicted_node"],
                reason=raw["reason"],
                timestamp=raw["timestamp"],
            )
        if event_type == EventType.SESSION_LIFECYCLE.value:
            principal = raw["principal"]
            return SessionLifecycleEvent(
                session_id=SessionId(raw["session_id"]),
                principal=Principal(principal) if principal is not None else None,
                action=raw["action"],
                timestamp=raw["timestamp"],
            )
    except (KeyError, ValueError, TypeError) as exc:
        raise AuditFormatError(f"malformed {event_type} record: {exc}") from exc
    raise AuditFormatError(f"unknown event type {event_type!r}")
