"""Loopback transport — the D11 PRIMARY path.

The monitor runs as its own process and exposes a decision-and-dispatch endpoint on loopback.
The agent process serializes proposals to JSON and POSTs them; it cannot import `tools` or
`policy` because they exist only in the monitor process (true OS-level isolation — this is the
tamper-resistance claim's strongest form, docs/design/architecture.md §4).

Uses stdlib HTTP + JSON only — NO new dependency (working agreement). The client half imports
only `contract`/`client`; the server half imports `monitor.service`. Split so the client is
safe for the agent process to load.
"""

from __future__ import annotations

from src.monitor.service import MonitorService
from src.transport.contract import SessionHandle, ToolCallProposal, ToolResult


class LoopbackTransport:
    """Client half: a `Transport` that talks to the monitor over loopback HTTP.

    Imports only `contract` + stdlib http/json at runtime. Lives in the agent process.
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8787") -> None:
        raise NotImplementedError

    def open_session(self) -> SessionHandle:
        """POST /session → monitor-assigned handle (D12.2)."""
        raise NotImplementedError

    def dispatch(self, proposal: ToolCallProposal, session: SessionHandle) -> ToolResult:
        """POST /dispatch with the JSON-serialized proposal; return the decoded ToolResult."""
        raise NotImplementedError


class LoopbackServer:
    """Server half: binds the loopback endpoint and routes requests to `MonitorService`. Runs
    in the MONITOR process. Uses stdlib `http.server` / `wsgiref` — no new dependency."""

    def __init__(self, service: MonitorService, host: str = "127.0.0.1", port: int = 8787) -> None:
        raise NotImplementedError

    def serve_forever(self) -> None:
        raise NotImplementedError
