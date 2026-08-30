"""Tool protocol and registry.

The registry is the monitor's private map from tool name to implementation. Only
`MonitorService` holds one. A lookup miss is handled by the service as DENY (unknown tool),
never an exception.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol, runtime_checkable

from src.transport.contract import ToolSpec


@runtime_checkable
class Tool(Protocol):
    """A mock tool: a stable name, the argument names it accepts, and an `execute` over
    in-process state.

    `execute` returns only the domain payload; the service wraps it into a `ToolResult`
    alongside the permitting Decision. The monitor-resolved `principal` (the account the call
    acts against) is passed in — the tool never reads identity from agent-supplied args.

    `args` is documentation of the call shape, NOT validation: `execute` still reads arguments
    defensively, and the monitor — not this declaration — decides what may run.
    """

    @property
    def name(self) -> str: ...

    args: tuple[str, ...]

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        """Run the tool and return its payload. Called ONLY after a permitting Decision
        (complete mediation)."""
        ...


class ToolRegistry:
    """Name → Tool. Owned by the monitor; never imported by the agent."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        """Return the tool for `name`, or None (the service turns None into an unknown-tool
        DENY, not a crash)."""
        return self._tools.get(name)

    def specs(self) -> tuple[ToolSpec, ...]:
        """The registered tools as agent-safe `ToolSpec`s, sorted by name.

        This is the catalog the composition root hands to a live model so it can name real
        tools instead of guessing. It exposes only names and argument names — never a verdict,
        a policy rule, or an implementation — and it is the SAME catalog for every scenario,
        benign or attack. Knowing a tool exists is not permission to call it.
        """
        return tuple(
            ToolSpec(name=name, args=tuple(getattr(tool, "args", ())))
            for name, tool in sorted(self._tools.items())
        )
