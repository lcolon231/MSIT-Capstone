"""In-process transport (D11 scope cut) and the agent-facing `Transport` protocol.

`InProcessTransport` must forward exactly once to `MonitorService` and add nothing of its own:
no verdict, no retry, no session minting through `dispatch`. Both concrete transports must
satisfy the neutral `Transport` protocol the agent is typed against.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from src.transport.client import Transport
from src.transport.contract import (
    DecisionSummary,
    ResultStatus,
    SessionHandle,
    ToolCallProposal,
    ToolResult,
    Verdict,
)
from src.transport.inprocess import InProcessTransport
from src.transport.loopback import LoopbackTransport

DENIED = ToolResult(ResultStatus.DENIED, DecisionSummary(Verdict.DENY, "default", "no"))


class FakeService:
    """Stands in for MonitorService; records every call."""

    def __init__(self, result: ToolResult = DENIED) -> None:
        self.result = result
        self.handled: list[tuple[ToolCallProposal, SessionHandle]] = []
        self.opened = 0

    def open_session(self) -> SessionHandle:
        self.opened += 1
        return SessionHandle(f"tok-{self.opened}")

    def handle(self, proposal: ToolCallProposal, session: SessionHandle) -> ToolResult:
        self.handled.append((proposal, session))
        return self.result


class RaisingService(FakeService):
    def handle(self, proposal: ToolCallProposal, session: SessionHandle) -> ToolResult:
        raise RuntimeError("monitor crashed")


def make(service: Any) -> InProcessTransport:
    return InProcessTransport(service)


def test_inprocess_open_session_delegates_to_service() -> None:
    service = FakeService()
    assert make(service).open_session() == SessionHandle("tok-1")
    assert service.opened == 1


def test_inprocess_dispatch_forwards_exactly_once_and_returns_service_result() -> None:
    service = FakeService()
    proposal, session = ToolCallProposal("t", {"a": 1}), SessionHandle("tok")
    assert make(service).dispatch(proposal, session) is DENIED
    assert service.handled == [(proposal, session)]


def test_inprocess_dispatch_does_not_open_a_session() -> None:
    service = FakeService()
    make(service).dispatch(ToolCallProposal("t", {}), SessionHandle("tok"))
    assert service.opened == 0


def test_inprocess_dispatch_propagates_service_errors_rather_than_inventing_a_result() -> None:
    # The service owns the fail-closed backstop; the transport must not swallow a failure into
    # a fabricated (possibly ALLOW) result.
    with pytest.raises(RuntimeError):
        make(RaisingService()).dispatch(ToolCallProposal("t", {}), SessionHandle("tok"))


@pytest.mark.parametrize("transport_cls", [InProcessTransport, LoopbackTransport])
def test_concrete_transports_expose_the_transport_protocol_methods(transport_cls: type) -> None:
    for name in ("open_session", "dispatch"):
        assert callable(getattr(transport_cls, name))
        proto = inspect.signature(getattr(Transport, name)).parameters
        impl = inspect.signature(getattr(transport_cls, name)).parameters
        assert list(impl) == list(proto)


def test_transport_protocol_has_no_session_choice_or_verdict_methods() -> None:
    public = {n for n in vars(Transport) if not n.startswith("_")}
    assert public == {"open_session", "dispatch"}
