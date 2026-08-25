"""Pluggable model interface (D4).

`ModelClient` is a thin protocol so any Ollama tool-calling model (Llama 3.1 8B as the concrete
target) is swappable, with a deterministic `StubModel` for CI. THE ONLY LLM IN THE SYSTEM lives
behind this interface, on the agent side of the transport boundary — never in the enforcement or
scoring path (spec.md §10, docs/design/architecture.md §1).

Imports only stdlib + `transport.contract` (the DTOs it proposes). No monitor/tools/policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence, runtime_checkable

from src.transport.contract import ToolCallProposal, ToolResult


@dataclass(frozen=True)
class ModelResponse:
    """A model turn: either propose a tool call, or finish with a final message."""

    proposal: ToolCallProposal | None
    final_text: str | None


@runtime_checkable
class ModelClient(Protocol):
    """Turns task context + prior results into the next proposal or a final answer."""

    def next_step(self, task: str, history: Sequence[ToolResult]) -> ModelResponse: ...


class OllamaModel:
    """Adapter for Ollama (Llama 3.1 8B, Q4). Concrete build target (D4)."""

    def __init__(self, model: str = "llama3.1:8b", host: str = "http://localhost:11434") -> None:
        raise NotImplementedError

    def next_step(self, task: str, history: Sequence[ToolResult]) -> ModelResponse:
        raise NotImplementedError


class StubModel:
    """Deterministic scripted model for CI — no live inference, reproducible runs."""

    def __init__(self, script: Sequence[ModelResponse]) -> None:
        raise NotImplementedError

    def next_step(self, task: str, history: Sequence[ToolResult]) -> ModelResponse:
        raise NotImplementedError
