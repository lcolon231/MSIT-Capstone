"""The `Transport` protocol — the boundary contract the agent programs against.

Abstract only. Implementation-free so that importing it (as the agent does) never pulls in
`monitor`, `tools`, or `policy`. Concrete transports live in `inprocess.py` / `loopback.py`
and are injected into the agent by the composition root (docs/design/architecture.md §3.2).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from src.transport.contract import SessionHandle, ToolCallProposal, ToolResult


@runtime_checkable
class Transport(Protocol):
    """Everything the agent is allowed to do to reach a tool: open a session and dispatch
    proposals. The agent never learns whether the other side is in-process or over loopback."""

    def open_session(self) -> SessionHandle:
        """Ask the monitor to assign a new session identity (D12.2). The agent cannot supply
        or choose it."""
        ...

    def dispatch(self, proposal: ToolCallProposal, session: SessionHandle) -> ToolResult:
        """Propose a tool call. The monitor evaluates it, executes it iff permitted, and
        returns the result. Complete mediation: there is no other path to a tool."""
        ...
