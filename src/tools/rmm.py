"""RMM mock domain — the healthcare-MSP kill-chain surface (spec.md T3.2).

Models a Remote Monitoring & Management agent acting on a managed client's endpoints. Each tool
passes per-call policy on its own; only the composition is the attack: reconnaissance
(`list_endpoints`, `list_shares`), registering a NEW export destination, then exfiltrating
patient records to THAT destination is the modeled fraud the sequence engine blocks
(docs/design/sequence-engine.md §4). `export_records` is a D5 data-export gate class; a legitimate
export to a pre-approved destination still routes to a human rather than being hard-blocked.

In-process only: no real endpoints, no filesystem, no egress — a "share" is a name and an
"export" only appends to an in-process log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from src.tools.base import ToolRegistry


@dataclass
class EndpointState:
    """In-process per-client (principal) state for the managed environment."""

    endpoints: dict[str, list[str]] = field(default_factory=dict)  # principal -> endpoint ids
    shares: dict[str, list[str]] = field(default_factory=dict)  # principal -> PHI share names
    destinations: dict[str, list[str]] = field(default_factory=dict)  # principal -> export dsts
    exported: list[tuple[str, str, int]] = field(default_factory=list)  # (principal, dst, records)


class ListEndpoints:
    name = "list_endpoints"  # benign recon
    args: tuple[str, ...] = ()

    def __init__(self, state: EndpointState) -> None:
        self._state = state

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        return {"endpoints": sorted(self._state.endpoints.get(principal, []))}


class ListShares:
    name = "list_shares"  # benign recon: enumerate PHI shares
    args: tuple[str, ...] = ()

    def __init__(self, state: EndpointState) -> None:
        self._state = state

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        return {"shares": sorted(self._state.shares.get(principal, []))}


class RegisterDestination:
    name = "register_destination"  # add a NEW export destination (binds it for the chain)
    args: tuple[str, ...] = ("destination",)

    def __init__(self, state: EndpointState) -> None:
        self._state = state

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        destination = str(args.get("destination", ""))
        registered = self._state.destinations.setdefault(principal, [])
        if destination and destination not in registered:
            registered.append(destination)
        return {"destinations": list(registered)}


class ExportRecords:
    name = "export_records"  # D5 data-export gate class (exfiltration of patient records)
    args: tuple[str, ...] = ("to", "count")

    def __init__(self, state: EndpointState) -> None:
        self._state = state

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        destination = str(args.get("to", ""))
        count = int(args.get("count", 0))
        self._state.exported.append((principal, destination, count))
        return {"exported": count, "to": destination}


class DisableLogging:
    name = "disable_logging"  # anti-forensics — never a legitimate agent action (DENY)
    args: tuple[str, ...] = ()

    def __init__(self, state: EndpointState) -> None:
        self._state = state

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        return {"logging": "disabled"}  # unreachable: per-call policy DENYs this outright


def rmm_tools(state: EndpointState) -> tuple[
    ListEndpoints, ListShares, RegisterDestination, ExportRecords, DisableLogging
]:
    """Construct the RMM tools sharing one in-process managed-environment state."""
    return (
        ListEndpoints(state),
        ListShares(state),
        RegisterDestination(state),
        ExportRecords(state),
        DisableLogging(state),
    )


def register_rmm(registry: ToolRegistry, state: EndpointState) -> None:
    """Register the RMM domain into a monitor `ToolRegistry`."""
    for tool in rmm_tools(state):
        registry.register(tool)
