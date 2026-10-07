"""Shared audit-event builders for the #9 tests (not a test module)."""

from __future__ import annotations

from typing import Any

from src.audit.events import (
    ChainProgressEvent,
    DecisionEvent,
    EvictionEvent,
    SessionLifecycleEvent,
    ToolExecutionEvent,
)
from src.monitor.types import CallId, GateClass, Principal, SessionId, ToolCall
from src.transport.contract import Verdict


def make_call(tool: str = "export_records", **args: object) -> ToolCall:
    return ToolCall(
        tool=tool,
        args=args or {"account": "SECRET-IBAN-123", "amount": 9999},
        session_id=SessionId("s1"),
        principal=Principal("client-1"),
        call_id=CallId("c1"),
        timestamp=1.0,
    )


def decision_ev(**over: Any) -> DecisionEvent:
    base: dict[str, Any] = dict(
        call_id="c1",
        session_id=SessionId("s1"),
        principal=Principal("client-1"),
        tool="export_records",
        arg_sha256="deadbeef",
        verdict=Verdict.GATE,
        rule_id="rmm.export_records.gate",
        reason="matched rule",
        gate_class=GateClass.DATA_EXPORT,
        timestamp=1.0,
    )
    base.update(over)
    return DecisionEvent(**base)


def chain_ev() -> ChainProgressEvent:
    return ChainProgressEvent(
        session_id=SessionId("s1"),
        principal=Principal("client-1"),
        chain="recon_register_exfil",
        from_node="registered_destination",
        to_node="drained",
        bindings={"registered_destination": "cafebabe"},
        timestamp=2.0,
    )


def eviction_ev() -> EvictionEvent:
    return EvictionEvent(
        session_id=SessionId("s1"),
        principal=Principal("client-1"),
        chain="recon_register_exfil",
        evicted_node="recon",
        reason="chain cap exceeded",
        timestamp=3.0,
    )


def lifecycle_ev() -> SessionLifecycleEvent:
    return SessionLifecycleEvent(
        session_id=SessionId("s1"),
        principal=Principal("client-1"),
        action="open",
        timestamp=4.0,
    )


def tool_exec_ev(status: str = "executed", result: str | None = "beef") -> ToolExecutionEvent:
    return ToolExecutionEvent(
        call_id="c1",
        session_id=SessionId("s1"),
        principal=Principal("client-1"),
        tool="list_shares",
        status=status,
        result_sha256=result,
        timestamp=3.0,
    )
