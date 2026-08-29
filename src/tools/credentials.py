"""Credentials mock domain — the CREDENTIAL_ACCESS gate class (D5).

Minimal in-process secret store with one GATE-class operation, `access_credential`, so the
credential-access class routes through the approval gate end-to-end (issue #13, criterion 1).
The secret VALUE is never returned or logged — only whether it exists — so the mock cannot leak
credentials. Expanded in #16.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from src.tools.base import ToolRegistry


@dataclass
class CredentialStore:
    """In-process secrets. Access is recorded; the value is never emitted."""

    secrets: dict[str, str] = field(default_factory=dict)  # name -> value (never returned)
    accesses: list[tuple[str, str]] = field(default_factory=list)  # (principal, name)


class AccessCredential:
    name = "access_credential"  # D5 credential-access gate class

    def __init__(self, store: CredentialStore) -> None:
        self._store = store

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        name = str(args.get("name", ""))
        self._store.accesses.append((principal, name))
        return {"accessed": name, "present": name in self._store.secrets}


def register_credentials(registry: ToolRegistry, store: CredentialStore) -> None:
    """Register the credentials domain into a monitor `ToolRegistry`."""
    registry.register(AccessCredential(store))
