"""Credentials mock domain (issue #16) — names may be listed; a secret VALUE is never emitted."""

from __future__ import annotations

import uuid

import pytest

from src.tools.base import ToolRegistry
from src.tools.credentials import (
    AccessCredential,
    CredentialStore,
    ListCredentials,
    register_credentials,
)

# A unique sentinel generated per run: easy to search for in any output, and no secret-shaped
# literal in the source for scanners to flag.
SECRET = f"sentinel-{uuid.uuid4().hex}"


def store() -> CredentialStore:
    return CredentialStore(secrets={"ehr-db": SECRET, "backup": "other"})


def test_list_credentials_returns_sorted_names_only() -> None:
    result = ListCredentials(store()).execute({}, "c1")
    assert result == {"names": ["backup", "ehr-db"]}
    assert SECRET not in str(result)


def test_access_credential_present_reports_presence_without_value() -> None:
    result = AccessCredential(store()).execute({"name": "ehr-db"}, "c1")
    assert result == {"accessed": "ehr-db", "present": True}
    assert SECRET not in str(result)


def test_access_credential_missing_reports_absent() -> None:
    assert AccessCredential(store()).execute({"name": "nope"}, "c1")["present"] is False


@pytest.mark.parametrize("name", ["ehr-db", "nope", ""])
def test_access_credential_records_every_access_with_principal(name: str) -> None:
    s = store()
    AccessCredential(s).execute({"name": name}, "c1")
    assert s.accesses == [("c1", name)]


def test_access_credential_value_never_reaches_access_log() -> None:
    s = store()
    AccessCredential(s).execute({"name": "ehr-db"}, "c1")
    assert SECRET not in str(s.accesses)


def test_register_credentials_registers_list_and_access() -> None:
    registry = ToolRegistry()
    register_credentials(registry, CredentialStore())
    assert [spec.name for spec in registry.specs()] == ["access_credential", "list_credentials"]
