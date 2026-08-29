"""Files mock domain — the FILE_DELETE gate class (D5).

Minimal in-process file store with one GATE-class operation, `delete_file`, so the file-delete
class routes through the approval gate end-to-end (issue #13, criterion 1). Additional file
operations and richer state are the domain's job in #16; here it exists to exercise the gate.
No real filesystem, no egress.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from src.tools.base import ToolRegistry


@dataclass
class FileStore:
    """In-process per-principal file listing. Deletion removes a path from the listing."""

    files: dict[str, list[str]] = field(default_factory=dict)  # principal -> existing paths


class DeleteFile:
    name = "delete_file"  # D5 file-delete gate class

    def __init__(self, store: FileStore) -> None:
        self._store = store

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        path = str(args.get("path", ""))
        listing = self._store.files.setdefault(principal, [])
        existed = path in listing
        if existed:
            listing.remove(path)
        return {"deleted": path, "existed": existed}


def register_files(registry: ToolRegistry, store: FileStore) -> None:
    """Register the files domain into a monitor `ToolRegistry`."""
    registry.register(DeleteFile(store))
