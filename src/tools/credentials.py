"""Credentials mock domain (issue #16, T4.4).

An in-process secret store. Listing credential NAMES is benign and ALLOWed; retrieving a secret
is the GATE-class operation `access_credential` (D5 credential-access). The secret VALUE is never
returned or logged — only its name and whether it exists — so the mock cannot leak credentials.
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


class ListCredentials:
    name = "list_credentials"  # benign: names only, never values

    def __init__(self, store: CredentialStore) -> None:
        self._store = store

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        return {"names": sorted(self._store.secrets)}


class AccessCredential:
    name = "access_credential"  # D5 credential-access gate class

    def __init__(self, store: CredentialStore) -> None:
        self._store = store

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        name = str(args.get("name", ""))
        self._store.accesses.append((principal, name))
        return {"accessed": name, "present": name in self._store.secrets}


def register_credentials(registry: ToolRegistry, store: CredentialStore) -> None:
    """Register the credentials domain (list ALLOW + access GATE) into a `ToolRegistry`."""
    registry.register(ListCredentials(store))
    registry.register(AccessCredential(store))
