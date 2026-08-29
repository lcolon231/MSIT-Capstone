"""Network mock domain — the NETWORK_SEND gate class (D5).

Minimal in-process outbound log with one GATE-class operation, `send_network`, so the
network-send class routes through the approval gate end-to-end (issue #13, criterion 1). No real
sockets, no egress — a "send" only appends to an in-process log. Expanded in #16.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from src.tools.base import ToolRegistry


@dataclass
class NetworkLog:
    """In-process record of outbound sends. No packet ever leaves the process."""

    sent: list[tuple[str, str, int]] = field(default_factory=list)  # (principal, dest, bytes)


class SendNetwork:
    name = "send_network"  # D5 network-send gate class

    def __init__(self, log: NetworkLog) -> None:
        self._log = log

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        dest = str(args.get("dest", ""))
        payload = str(args.get("payload", ""))
        self._log.sent.append((principal, dest, len(payload)))
        return {"sent_to": dest, "bytes": len(payload)}


def register_network(registry: ToolRegistry, log: NetworkLog) -> None:
    """Register the network domain into a monitor `ToolRegistry`."""
    registry.register(SendNetwork(log))
