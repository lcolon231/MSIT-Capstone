"""Pluggable model interface (D4).

`ModelClient` is a thin protocol so any Ollama tool-calling model (Llama 3.1 8B as the concrete
target) is swappable, with a deterministic `StubModel` for CI. THE ONLY LLM IN THE SYSTEM lives
behind this interface, on the agent side of the transport boundary — never in the enforcement or
scoring path (spec.md §10, docs/design/architecture.md §1).

Imports only stdlib + `transport.contract` (the DTOs it proposes). No monitor/tools/policy.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol, Sequence, runtime_checkable

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


class ModelError(RuntimeError):
    """The Ollama backend was unreachable or returned an unusable response."""


class StubModel:
    """Deterministic scripted model for CI — no live inference, reproducible runs.

    The response for a step is chosen by how many results have been observed, so a run is a pure
    function of the script: step *i* returns ``script[i]`` and, once the script is exhausted, a
    final message. This is what lets the integration test assert exact mediation outcomes without
    a live model."""

    def __init__(self, script: Sequence[ModelResponse], done_text: str = "done") -> None:
        self._script = tuple(script)
        self._done_text = done_text

    def next_step(self, task: str, history: Sequence[ToolResult]) -> ModelResponse:
        step = len(history)
        if step < len(self._script):
            return self._script[step]
        return ModelResponse(proposal=None, final_text=self._done_text)


class OllamaModel:
    """Adapter for Ollama (Llama 3.1 8B, Q4). Concrete build target (D4).

    Talks to a local Ollama server over stdlib HTTP (no new dependency). The model is asked to
    reply with a single JSON object — ``{"tool": name, "args": {...}}`` to act, or
    ``{"final": text}`` to finish — parsed into a `ModelResponse`. It lives entirely on the agent
    side of the transport boundary; the monitor still mediates whatever it proposes. Not exercised
    in CI (requires a running Ollama) — `StubModel` covers the loop there."""

    _SYSTEM = (
        "You are an agent that acts only by emitting ONE JSON object per turn and nothing else. "
        'To call a tool: {"tool": "<name>", "args": {<key>: <value>}}. '
        'When the task is complete: {"final": "<short summary>"}. '
        "Do not wrap the JSON in prose or code fences."
    )

    def __init__(self, model: str = "llama3.1:8b", host: str = "http://localhost:11434") -> None:
        self._model = model
        self._host = host.rstrip("/")

    def next_step(self, task: str, history: Sequence[ToolResult]) -> ModelResponse:
        payload = {
            "model": self._model,
            "stream": False,
            "format": "json",
            "messages": [
                {"role": "system", "content": self._SYSTEM},
                {"role": "user", "content": self._render(task, history)},
            ],
        }
        raw = self._post("/api/chat", payload)
        content = raw.get("message", {}).get("content", "")
        return self._parse(content)

    def _render(self, task: str, history: Sequence[ToolResult]) -> str:
        lines = [f"Task: {task}", "", "Observations so far:"]
        if not history:
            lines.append("(none yet)")
        for i, result in enumerate(history, 1):
            lines.append(f"{i}. {result.status.value}: {result.decision.reason} (rule {result.decision.rule_id})")
        lines.append("")
        lines.append("Emit the next JSON object.")
        return "\n".join(lines)

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{self._host}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ModelError(f"Ollama request to {self._host}{path} failed: {exc}") from exc
        if not isinstance(decoded, dict):
            raise ModelError("Ollama returned a non-object response")
        return decoded

    @staticmethod
    def _parse(content: str) -> ModelResponse:
        try:
            obj = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ModelError(f"model did not emit valid JSON: {content!r}") from exc
        if isinstance(obj, dict) and "tool" in obj:
            args = obj.get("args") or {}
            if not isinstance(args, dict):
                raise ModelError("model 'args' must be an object")
            return ModelResponse(proposal=ToolCallProposal(tool=str(obj["tool"]), args=args), final_text=None)
        if isinstance(obj, dict) and "final" in obj:
            return ModelResponse(proposal=None, final_text=str(obj["final"]))
        raise ModelError(f"model JSON had neither 'tool' nor 'final': {content!r}")
