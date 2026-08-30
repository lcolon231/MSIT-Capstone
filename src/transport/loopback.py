"""Loopback transport — client half of the D11 PRIMARY path.

The monitor runs as its own OS process and exposes a decision-and-dispatch endpoint on
loopback (see ``src/transport/loopback_server.py``). This client lives in the AGENT process:
it serializes a proposal to JSON, POSTs it over loopback, and decodes the ``ToolResult``. Tools
and policy objects exist only in the monitor process, so a compromised agent has no in-memory
object to reach — this is the tamper-resistance claim's strongest form
(docs/design/architecture.md §3.3, §4).

Imports ``contract`` + stdlib HTTP/JSON **only** — NO ``monitor`` import, no new dependency
(working agreement). ``tests/test_import_graph.py`` asserts this module's transitive closure
never reaches ``monitor`` / ``tools`` / ``policy``; that assertion is what makes the isolation
claim self-enforcing.
"""

from __future__ import annotations

import http.client
import json
from urllib.parse import urlsplit

from src.transport.contract import (
    SessionHandle,
    ToolCallProposal,
    ToolResult,
    proposal_to_wire,
    result_from_wire,
)

# Header carrying the launcher's bootstrap capability. Session creation is a trusted-launcher
# action, not an agent one (D14): only a holder of this capability may open a session. It is
# injected into the concrete transport by the composition root, never model context.
BOOTSTRAP_HEADER = "X-Bootstrap-Capability"


class LoopbackError(RuntimeError):
    """Raised when the loopback endpoint is unreachable or returns a non-2xx/undecodable
    response. Kept distinct so the launcher/tests can tell a transport fault from a monitor
    DENY (a DENY is a normal, decodable ``ToolResult``)."""


class LoopbackTransport:
    """Client half: a `Transport` that talks to the monitor over loopback HTTP.

    Holds the endpoint URL and the launcher-issued bootstrap capability. Imports only
    ``contract`` + stdlib http/json. Lives in the agent process.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8787",
        capability: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme != "http" or not parts.hostname:
            raise LoopbackError(f"loopback base_url must be http://host:port, got {base_url!r}")
        self._host = parts.hostname
        self._port = parts.port or 8787
        self._capability = capability
        self._timeout = timeout

    def open_session(self) -> SessionHandle:
        """POST /session → monitor-assigned handle (D12.2). Presents the bootstrap capability;
        without it the monitor refuses to mint a session."""
        headers = {BOOTSTRAP_HEADER: self._capability} if self._capability else {}
        body = self._post("/session", {}, headers)
        token = body.get("token")
        if not isinstance(token, str):
            raise LoopbackError("monitor did not return a session token")
        return SessionHandle(token=token)

    def dispatch(self, proposal: ToolCallProposal, session: SessionHandle) -> ToolResult:
        """POST /dispatch with the JSON-serialized proposal + session token; return the decoded
        ToolResult. A monitor DENY comes back as an ordinary decodable result, not an error."""
        payload = {"proposal": proposal_to_wire(proposal), "session": session.token}
        body = self._post("/dispatch", payload, {})
        try:
            return result_from_wire(body)
        except (KeyError, ValueError) as exc:  # undecodable monitor response
            raise LoopbackError(f"malformed ToolResult from monitor: {exc}") from exc

    def _post(self, path: str, payload: dict, headers: dict[str, str]) -> dict:
        """POST a JSON body to the loopback endpoint and return the decoded JSON object."""
        data = json.dumps(payload).encode("utf-8")
        conn = http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)
        try:
            conn.request(
                "POST",
                path,
                body=data,
                headers={"Content-Type": "application/json", **headers},
            )
            response = conn.getresponse()
            raw = response.read()
            if response.status // 100 != 2:
                raise LoopbackError(f"{path} returned HTTP {response.status}: {raw[:200]!r}")
            decoded = json.loads(raw or b"{}")
            if not isinstance(decoded, dict):
                raise LoopbackError(f"{path} returned non-object JSON")
            return decoded
        except OSError as exc:  # connection refused, reset, timeout
            raise LoopbackError(f"loopback endpoint unreachable at {path}: {exc}") from exc
        finally:
            conn.close()


def wait_until_ready(base_url: str, timeout_s: float = 10.0, interval_s: float = 0.05) -> bool:
    """Poll GET /health until the monitor process is accepting connections, or the deadline
    passes. Used by the trusted launcher/tests after spawning the server subprocess. Returns
    True once ready; False on timeout."""
    import time

    parts = urlsplit(base_url)
    host, port = parts.hostname or "127.0.0.1", parts.port or 8787
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        conn = http.client.HTTPConnection(host, port, timeout=interval_s * 4)
        try:
            conn.request("GET", "/health")
            if conn.getresponse().status == 200:
                return True
        except OSError:
            time.sleep(interval_s)
        finally:
            conn.close()
    return False
