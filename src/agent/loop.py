"""The agent loop.

Turns a task into a series of `ToolCallProposal`s, dispatches each over the injected
`Transport`, feeds the `ToolResult` back to the model, and repeats until the model finishes.

The agent NEVER calls a tool and never sees a Decision's internals — only the redacted
`ToolResult` (D11). The `Transport` and `ModelClient` are injected by the composition root;
this module imports nothing from `tools`, `policy`, or `monitor`.
"""

from __future__ import annotations

from src.agent.model import ModelClient
from src.transport.client import Transport


class Agent:
    """Drives a task to completion through the monitor's mediated dispatch."""

    def __init__(self, model: ModelClient, transport: Transport) -> None:
        raise NotImplementedError

    def run(self, task: str, max_steps: int = 25) -> str:
        """Execute `task`: propose → dispatch → observe → repeat. Returns the model's final
        text. A DENY/GATE result is fed back like any other observation — the agent cannot
        override it."""
        raise NotImplementedError
