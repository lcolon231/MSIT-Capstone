"""Loopback transport — monitor-side HTTP adapter (D11 PRIMARY, architecture.md §3.3a).

The server half of the loopback path. It runs ONLY in the monitor process: it decodes
loopback requests, enforces the launcher-only bootstrap capability on session creation,
validates the session on dispatch, and delegates to `MonitorService.handle`. Decoded input —
including malformed shapes — is handed to the service's own normalization boundary; a bad
request becomes a DENY `ToolResult`, never an HTTP-path exception that could bypass mediation.

Split out of `loopback.py` on purpose (§3.3a): this module imports `MonitorService`, so the
client half must not, or importing the client would drag the monitor into the agent process
and defeat the OS boundary.

May import: `src/monitor/service`, `src/transport/contract`, stdlib HTTP/JSON.
Must never import: `src/agent` — it has no place in the untrusted process.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from src.monitor.service import MonitorService
from src.transport.contract import SessionHandle, proposal_from_wire, result_to_wire
from src.transport.loopback import BOOTSTRAP_HEADER


class _MonitorHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server carrying the monitor service and the bootstrap capability so the
    per-request handler can reach them via ``self.server``."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        addr: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        service: MonitorService,
        capability: str | None,
    ) -> None:
        super().__init__(addr, handler)
        self.service = service
        self.capability = capability

    def handle_error(self, request: Any, client_address: Any) -> None:
        """A client that hangs up (agent process exiting, connection closed after a response) is
        benign — swallow the reset instead of dumping a traceback. Real faults still surface."""
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


class _LoopbackHandler(BaseHTTPRequestHandler):
    """Routes the three loopback endpoints. Every failure path is fail-closed: an unreachable
    branch, a bad body, or a bad session all resolve to a DENY result or a 4xx, never to tool
    execution."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # silence default stderr access logging
        pass

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path == "/session":
            self._handle_session()
        elif self.path == "/dispatch":
            self._handle_dispatch()
        else:
            self._send_json(404, {"error": "not found"})

    # --- endpoints -------------------------------------------------------------------------

    def _handle_session(self) -> None:
        """Mint a session — a trusted-launcher action. Requires the bootstrap capability when the
        server was configured with one; a missing/incorrect capability is refused (no session,
        so nothing can dispatch)."""
        self._read_body()  # drain the request body regardless
        expected = self.server.capability  # type: ignore[attr-defined]
        if expected is not None and self.headers.get(BOOTSTRAP_HEADER) != expected:
            self._send_json(403, {"error": "invalid or missing bootstrap capability"})
            return
        handle = self.server.service.open_session()  # type: ignore[attr-defined]
        self._send_json(200, {"token": handle.token})

    def _handle_dispatch(self) -> None:
        """Decode {proposal, session} and delegate to the service. A malformed body or unknown
        session flows into the service's fail-closed path and returns a DENY result."""
        body = self._read_json()
        proposal = proposal_from_wire(body.get("proposal") if isinstance(body, dict) else None)
        token = body.get("session") if isinstance(body, dict) else None
        session = SessionHandle(token=str(token) if isinstance(token, str) else "")
        result = self.server.service.handle(proposal, session)  # type: ignore[attr-defined]
        self._send_json(200, result_to_wire(result))

    # --- IO helpers ------------------------------------------------------------------------

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length) if length > 0 else b""

    def _read_json(self) -> object:
        try:
            return json.loads(self._read_body() or b"{}")
        except (ValueError, TypeError):
            return {}

    def _send_json(self, status: int, payload: object) -> None:
        data = json.dumps(payload).encode("utf-8")
        # The client opens a fresh connection per call, so close after each response rather than
        # holding a keep-alive socket open (which just races the client's close → a reset).
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)


class LoopbackServer:
    """Server half: binds the loopback endpoint and routes requests to `MonitorService`. Runs in
    the MONITOR process. Uses stdlib `http.server` — no new dependency.

    `capability`, when set, is the launcher-only bootstrap secret required to open a session.
    """

    def __init__(
        self,
        service: MonitorService,
        host: str = "127.0.0.1",
        port: int = 8787,
        capability: str | None = None,
    ) -> None:
        self._httpd = _MonitorHTTPServer((host, port), _LoopbackHandler, service, capability)

    @property
    def port(self) -> int:
        """The bound port (useful when constructed with port 0 to get an ephemeral port)."""
        return self._httpd.server_address[1]

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address[0], self._httpd.server_address[1]
        if isinstance(host, (bytes, bytearray)):
            host = host.decode()
        return f"http://{host}:{port}"

    def serve_forever(self) -> None:
        """Serve until `shutdown()` is called (blocking)."""
        self._httpd.serve_forever()

    def shutdown(self) -> None:
        """Stop serving and release the socket. Safe to call from another thread."""
        self._httpd.shutdown()
        self._httpd.server_close()
