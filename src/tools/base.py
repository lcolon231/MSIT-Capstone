"""Tool protocol and registry.

The registry is the monitor's private map from tool name to implementation. Only
`MonitorService` holds one. A lookup miss is handled by the service as DENY (unknown tool),
never an exception.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol, runtime_checkable

from src.transport.contract import ToolResult


@runtime_checkable
class Tool(Protocol):
    """A mock tool: a stable name and a pure-ish `execute` over in-process state."""

    @property
    def name(self) -> str: ...

    def execute(self, args: Mapping[str, Any]) -> ToolResult:
        """Run the tool. Called ONLY after a permitting Decision (complete mediation)."""
        ...


class ToolRegistry:
    """Name → Tool. Owned by the monitor; never imported by the agent."""

    def register(self, tool: Tool) -> None:
        raise NotImplementedError

    def get(self, name: str) -> Tool | None:
        """Return the tool for `name`, or None (the service turns None into an unknown-tool
        DENY, not a crash)."""
        raise NotImplementedError
