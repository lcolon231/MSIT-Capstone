"""Tool protocol and registry.

The registry is the monitor's private map from tool name to implementation. Only
`MonitorService` holds one. A lookup miss is handled by the service as DENY (unknown tool),
never an exception.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol, runtime_checkable


@runtime_checkable
class Tool(Protocol):
    """A mock tool: a stable name and an `execute` over in-process state.

    `execute` returns only the domain payload; the service wraps it into a `ToolResult`
    alongside the permitting Decision. The monitor-resolved `principal` (the account the call
    acts against) is passed in — the tool never reads identity from agent-supplied args.
    """

    @property
    def name(self) -> str: ...

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
