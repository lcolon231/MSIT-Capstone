"""The agent loop.

Turns a task into a series of `ToolCallProposal`s, dispatches each over the injected
`Transport`, feeds the `ToolResult` back to the model, and repeats until the model finishes.

The agent NEVER calls a tool and never sees a Decision's internals — only the redacted
`ToolResult` (D11). The `Transport` and `ModelClient` are injected by the composition root;
this module imports nothing from `tools`, `policy`, or `monitor`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.agent.model import ModelClient
from src.transport.client import Transport
from src.transport.contract import ToolCallProposal, ToolResult


@dataclass(frozen=True)
class AgentRun:
    """The record of one completed run: the final text plus the ordered (proposal, result)
    pairs, so a caller can inspect exactly what was mediated. The agent only ever sees the
    redacted `ToolResult` — never a Decision's internals (D11)."""

    final_text: str
    steps: tuple[tuple[ToolCallProposal, ToolResult], ...] = field(default_factory=tuple)


class Agent:
    """Drives a task to completion through the monitor's mediated dispatch."""

    def __init__(self, model: ModelClient, transport: Transport) -> None:
        self._model = model
        self._transport = transport

    def run(self, task: str, max_steps: int = 25) -> str:
        """Execute `task`: propose → dispatch → observe → repeat. Returns the model's final
        text. A DENY/GATE result is fed back like any other observation — the agent cannot
        override it."""
        return self.run_traced(task, max_steps).final_text

    def run_traced(self, task: str, max_steps: int = 25) -> AgentRun:
        """Like `run`, but also returns the (proposal, result) trace for inspection/tests. Every
        proposal goes over the transport — the ONLY path to a tool (complete mediation)."""
        session = self._transport.open_session()
        history: list[ToolResult] = []
        steps: list[tuple[ToolCallProposal, ToolResult]] = []
        for _ in range(max_steps):
            response = self._model.next_step(task, tuple(history))
            if response.proposal is None:
                return AgentRun(final_text=response.final_text or "", steps=tuple(steps))
            result = self._transport.dispatch(response.proposal, session)
            history.append(result)
            steps.append((response.proposal, result))
        return AgentRun(final_text="stopped: reached max_steps", steps=tuple(steps))
