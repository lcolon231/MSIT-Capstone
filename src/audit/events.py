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
from typing import Mapping

from src.monitor.types import GateClass, Principal, SessionId
from src.transport.contract import Verdict


class EventType(Enum):
    DECISION = "decision"
    CHAIN_PROGRESS = "chain_progress"
    EVICTION = "eviction"
    SESSION_LIFECYCLE = "session_lifecycle"
    APPROVAL_RESOLUTION = "approval_resolution"
    TOOL_EXECUTION = "tool_execution"


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
    """A sequence-state advance, sufficient to replay the automaton (D12.4).

    `bindings` maps each binding NAME to the canonical SHA-256 DIGEST of the bound value — never
    the plaintext — so replay can restore the exact binding a later step is compared against
    (interface-contracts.md §4.7). `from_node == to_node` records a re-bind on a repeated step."""

    type: EventType = field(default=EventType.CHAIN_PROGRESS, init=False)
    session_id: SessionId
    principal: Principal
    chain: str
    from_node: str
    to_node: str
    bindings: Mapping[str, str]
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


@dataclass(frozen=True)
class ApprovalResolutionEvent:
    """An operator (or timeout) resolving a GATE decision (D5). SEPARATE from the original
    DecisionEvent, which keeps its GATE verdict — this records only how the gate was resolved.
    `operator` is null on a timeout. `arg_sha256` is a hash, never plaintext (criterion #8)."""

    type: EventType = field(default=EventType.APPROVAL_RESOLUTION, init=False)
    approval_id: str
    call_id: str
    session_id: SessionId
    principal: Principal
    tool: str
    arg_sha256: str
    gate_class: GateClass
    resolution: str  # "approved" | "denied" | "timed_out"
    operator: str | None
    timestamp: float


@dataclass(frozen=True)
class ToolExecutionEvent:
    """What happened when a PERMITTED call reached its tool: "executed" or "failed". Written after
    the DecisionEvent, so the log distinguishes "allowed and ran" from "allowed but the tool
    raised". `result_sha256` digests the payload (None on failure) — never plaintext."""

    type: EventType = field(default=EventType.TOOL_EXECUTION, init=False)
    call_id: str
    session_id: SessionId
    principal: Principal
    tool: str
    status: str  # "executed" | "failed"
    result_sha256: str | None
    timestamp: float


AuditEvent = (
    DecisionEvent
    | ChainProgressEvent
    | EvictionEvent
    | SessionLifecycleEvent
    | ApprovalResolutionEvent
    | ToolExecutionEvent
)


class AuditFormatError(ValueError):
    """A log line is not a valid, complete audit record. Corrupt records fail closed and are
    never silently skipped (interface-contracts.md §4.7)."""


def _encode(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return dict(value)
    return value


def _digest_map(raw: object) -> dict[str, str]:
    """Validate a name -> digest mapping read back from the log (untrusted input)."""
    if not isinstance(raw, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in raw.items()
    ):
        raise ValueError("bindings must map binding names to digest strings")
    return dict(raw)


def to_dict(event: AuditEvent) -> dict[str, object]:
    """Serialize an event to a JSON-ready dict (enums flattened to their values). Pure.

    This is the single place that maps an event's dataclass fields to its on-disk shape. The
    audit writer reuses it to wrap each record in a tamper-evidence envelope (`prev_sha256` +
    `seq`, D-#56) without the event types themselves having to carry log-integrity fields."""
    return {f.name: _encode(getattr(event, f.name)) for f in dataclasses.fields(event)}


def to_jsonl(event: AuditEvent) -> str:
    """Serialize an event to a single JSONL line. Pure."""
    return json.dumps(to_dict(event), ensure_ascii=True, separators=(",", ":"))


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
                bindings=_digest_map(raw["bindings"]),
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
        if event_type == EventType.APPROVAL_RESOLUTION.value:
            operator = raw["operator"]
            return ApprovalResolutionEvent(
                approval_id=raw["approval_id"],
                call_id=raw["call_id"],
                session_id=SessionId(raw["session_id"]),
                principal=Principal(raw["principal"]),
                tool=raw["tool"],
                arg_sha256=raw["arg_sha256"],
                gate_class=GateClass(raw["gate_class"]),
                resolution=raw["resolution"],
                operator=operator if operator is None else str(operator),
                timestamp=raw["timestamp"],
            )
        if event_type == EventType.TOOL_EXECUTION.value:
            result = raw["result_sha256"]
            status = raw["status"]
            if status not in ("executed", "failed"):
                raise ValueError(f"unknown tool execution status {status!r}")
            return ToolExecutionEvent(
                call_id=raw["call_id"],
                session_id=SessionId(raw["session_id"]),
                principal=Principal(raw["principal"]),
                tool=raw["tool"],
                status=status,
                result_sha256=result if result is None else str(result),
                timestamp=raw["timestamp"],
            )
    except (KeyError, ValueError, TypeError) as exc:
        raise AuditFormatError(f"malformed {event_type} record: {exc}") from exc
    raise AuditFormatError(f"unknown event type {event_type!r}")
