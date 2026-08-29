"""Network mock domain (issue #16, T4.4).

No real sockets, no egress. A benign read-only `fetch_url` that per-call policy ALLOWs (it
returns a canned in-process body — nothing leaves the process) plus one GATE-class operation,
`send_network` (D5 network-send), for outbound data that must be human-approved.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from src.tools.base import ToolRegistry


@dataclass
class NetworkLog:
    """In-process record of network activity. No packet ever leaves the process."""

    sent: list[tuple[str, str, int]] = field(default_factory=list)  # (principal, dest, bytes)
    fetched: list[tuple[str, str]] = field(default_factory=list)  # (principal, url)


class FetchUrl:
    name = "fetch_url"  # benign read-only fetch (canned response, no real network)

    _CANNED_BODY = "mock-response-body"

    def __init__(self, log: NetworkLog) -> None:
        self._log = log

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        url = str(args.get("url", ""))
        self._log.fetched.append((principal, url))
        return {"url": url, "status": 200, "bytes": len(self._CANNED_BODY)}


class SendNetwork:
    name = "send_network"  # D5 network-send gate class (outbound egress)

    def __init__(self, log: NetworkLog) -> None:
        self._log = log

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        dest = str(args.get("dest", ""))
        payload = str(args.get("payload", ""))
        self._log.sent.append((principal, dest, len(payload)))
        return {"sent_to": dest, "bytes": len(payload)}


def register_network(registry: ToolRegistry, log: NetworkLog) -> None:
    """Register the network domain (fetch ALLOW + send GATE) into a `ToolRegistry`."""
    registry.register(FetchUrl(log))
    registry.register(SendNetwork(log))
