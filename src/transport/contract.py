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
class ToolSpec:
    """One tool the agent may name in a proposal: its exact name and accepted argument names.

    The monitor owns the tool registry; a catalog of these is handed to the agent so it can
    address real tools instead of inventing plausible-looking names. Deliberately carries NO
    verdict information: that a tool EXISTS says nothing about whether calling it will be
    permitted, and the catalog is identical under benign and attack conditions. The monitor
    still mediates every call (D11).
    """

    name: str
    args: tuple[str, ...] = ()


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
