"""In-process transport — the documented SCOPE CUT (D11).

Agent and monitor share one address space; `dispatch` calls `MonitorService.handle` directly.
Source-level isolation only (the seam), NOT address-space isolation — a compromised in-process
agent could reach objects it never imported. This is why loopback is the D11 primary
(docs/design/residual-risks.md, cross-cutting note).

Imports `monitor.service` — therefore MUST NOT be imported by `src/agent`. It is wired to the
agent by the composition root via the `Transport` protocol, never named in agent code.
"""

from __future__ import annotations

from src.monitor.service import MonitorService
from src.transport.contract import SessionHandle, ToolCallProposal, ToolResult


class InProcessTransport:
    """A `Transport` that forwards straight to the monitor in the same process."""

    def __init__(self, service: MonitorService) -> None:
        raise NotImplementedError

    def open_session(self) -> SessionHandle:
        raise NotImplementedError

    def dispatch(self, proposal: ToolCallProposal, session: SessionHandle) -> ToolResult:
        raise NotImplementedError
