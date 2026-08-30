"""Neutral, agent-safe DTOs that cross the transport boundary in both directions.

PURE LEAF: imports stdlib only, never anything else under ``src/``. This is what lets the
agent share a vocabulary with the monitor without ever gaining an import path to
``src/tools`` or ``src/policy`` (docs/design/architecture.md §3.1, §4).

Design invariant: a ``ToolCallProposal`` carries the tool name and arguments and NOTHING
that could influence a verdict — no session id, no principal, no ``approved`` flag. The
monitor assigns all identity on its own side (``ToolCall`` in ``monitor/types.py``).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


class Verdict(Enum):
    """The three possible outcomes of evaluating a tool call."""

    ALLOW = "allow"
    DENY = "deny"
    GATE = "gate"


class ResultStatus(Enum):
    """What actually happened to a proposed call, as reported back to the agent."""

    EXECUTED = "executed"  # verdict ALLOW (or GATE then approved); tool ran
    DENIED = "denied"  # verdict DENY, or GATE that was denied / timed out
    GATED_PENDING = "gated_pending"  # GATE awaiting operator; no result yet


@dataclass(frozen=True)
class ToolCallProposal:
    """What the agent emits. Tool name + arguments only — no identity, no verdict hints."""

    tool: str
    args: Mapping[str, Any]


@dataclass(frozen=True)
class SessionHandle:
    """Opaque, MONITOR-ISSUED session token (D12.2).

    The agent holds this and presents it on each dispatch, but cannot choose, forge a valid
    one, or use it to reset state. A fresh/rotated handle is re-seeded from the principal's
    audit history, so rotation buys the agent nothing (see docs/design/sequence-engine.md §3).
    """

    token: str


@dataclass(frozen=True)
class DecisionSummary:
    """The agent-visible, redacted view of a Decision. Enough to continue the loop; no policy
    internals beyond the traceable rule_id."""

    verdict: Verdict
    rule_id: str
    reason: str


@dataclass(frozen=True)
class ToolResult:
    """What the monitor returns to the agent for a single proposed call."""

    status: ResultStatus
    decision: DecisionSummary
    payload: Any = None  # tool output when EXECUTED; None otherwise


# --- wire codec (D11 loopback) -------------------------------------------------------------
# The single source of truth for the JSON shapes that cross the loopback boundary in both
# directions. Both transport halves import these; keeping the format here (stdlib/JSON only)
# is what lets the client half stay free of any `monitor` import. Decoding is fail-closed: a
# missing/malformed proposal degrades to an empty call the monitor will DENY, never an
# exception that could bypass mediation.


def proposal_to_wire(proposal: ToolCallProposal) -> dict[str, Any]:
    """Serialize a ``ToolCallProposal`` to a JSON-ready dict. Only tool + args cross — the same
    invariant as the DTO itself (no identity, no verdict hints)."""
    return {"tool": proposal.tool, "args": dict(proposal.args)}


def proposal_from_wire(data: Any) -> ToolCallProposal:
    """Rebuild a ``ToolCallProposal`` from decoded JSON, leniently. A non-object body, a missing
    ``tool``, or non-mapping ``args`` normalize to a call the monitor will reject on its own
    validation boundary — the server never raises on shape."""
    if not isinstance(data, Mapping):
        return ToolCallProposal(tool="", args={})
    raw_args = data.get("args")
    args = dict(raw_args) if isinstance(raw_args, Mapping) else {}
    return ToolCallProposal(tool=str(data.get("tool", "")), args=args)


def result_to_wire(result: ToolResult) -> dict[str, Any]:
    """Serialize a ``ToolResult`` (status + redacted decision + untrusted payload) to a
    JSON-ready dict."""
    return {
        "status": result.status.value,
        "decision": {
            "verdict": result.decision.verdict.value,
            "rule_id": result.decision.rule_id,
            "reason": result.decision.reason,
        },
        "payload": result.payload,
    }


def result_from_wire(data: Mapping[str, Any]) -> ToolResult:
    """Rebuild a ``ToolResult`` from decoded JSON. Used by the client half to turn the monitor's
    response back into the same DTO the in-process path returns."""
    decision = data["decision"]
    return ToolResult(
        status=ResultStatus(data["status"]),
        decision=DecisionSummary(
            verdict=Verdict(decision["verdict"]),
            rule_id=decision["rule_id"],
            reason=decision["reason"],
        ),
        payload=data.get("payload"),
    )
