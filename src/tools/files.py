"""Files mock domain (issue #16, T4.4).

An in-process per-principal file store — no real filesystem, no egress. Two benign read
operations that per-call policy ALLOWs (`list_files`, `read_file`) plus one irreversible
GATE-class operation, `delete_file` (D5 file-delete), that routes to a human.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from src.tools.base import ToolRegistry


@dataclass
class FileStore:
    """In-process per-principal files: principal -> {path: content}. No real filesystem."""

    files: dict[str, dict[str, str]] = field(default_factory=dict)

    def _for(self, principal: str) -> dict[str, str]:
        return self.files.setdefault(principal, {})


class ListFiles:
    name = "list_files"  # benign read

    def __init__(self, store: FileStore) -> None:
        self._store = store

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        return {"paths": sorted(self._store.files.get(principal, {}))}


class ReadFile:
    name = "read_file"  # benign read

    def __init__(self, store: FileStore) -> None:
        self._store = store

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        path = str(args.get("path", ""))
        files = self._store.files.get(principal, {})
        return {"path": path, "present": path in files, "content": files.get(path)}


class DeleteFile:
    name = "delete_file"  # D5 file-delete gate class (irreversible)

    def __init__(self, store: FileStore) -> None:
        self._store = store

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        path = str(args.get("path", ""))
        files = self._store._for(principal)
        existed = path in files
        files.pop(path, None)
        return {"deleted": path, "existed": existed}


def register_files(registry: ToolRegistry, store: FileStore) -> None:
    """Register the files domain (list/read ALLOW + delete GATE) into a `ToolRegistry`."""
    registry.register(ListFiles(store))
    registry.register(ReadFile(store))
    registry.register(DeleteFile(store))
