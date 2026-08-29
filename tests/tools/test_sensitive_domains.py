"""Files / network / credentials mock domains — issue #13 criterion 1 (one GATE-class op each).

These minimal tools give the file-delete, network-send, and credential-access gate classes a
real execution target so they route through the approval gate end-to-end. No filesystem, no
sockets, no credential leakage.
"""

from __future__ import annotations

from src.tools.base import ToolRegistry
from src.tools.credentials import AccessCredential, CredentialStore, register_credentials
from src.tools.files import DeleteFile, FileStore, register_files
from src.tools.network import NetworkLog, SendNetwork, register_network


def test_delete_file_removes_existing_path() -> None:
    store = FileStore(files={"acct-1": ["/a", "/b"]})
    assert DeleteFile(store).execute({"path": "/a"}, "acct-1") == {"deleted": "/a", "existed": True}
    assert store.files["acct-1"] == ["/b"]


def test_delete_missing_file_is_not_an_error() -> None:
    store = FileStore()
    assert DeleteFile(store).execute({"path": "/x"}, "acct-1")["existed"] is False


def test_send_network_records_bytes_without_egress() -> None:
    log = NetworkLog()
    result = SendNetwork(log).execute({"dest": "10.0.0.1", "payload": "hello"}, "acct-1")
    assert result == {"sent_to": "10.0.0.1", "bytes": 5}
    assert log.sent == [("acct-1", "10.0.0.1", 5)]


def test_access_credential_never_returns_the_value() -> None:
    store = CredentialStore(secrets={"db": "s3cr3t"})
    result = AccessCredential(store).execute({"name": "db"}, "acct-1")
    assert result == {"accessed": "db", "present": True}
    assert "s3cr3t" not in str(result)  # the value never leaves the store
    assert store.accesses == [("acct-1", "db")]


def test_register_helpers_populate_the_registry() -> None:
    registry = ToolRegistry()
    register_files(registry, FileStore())
    register_network(registry, NetworkLog())
    register_credentials(registry, CredentialStore())
    for name in ("delete_file", "send_network", "access_credential"):
        assert registry.get(name) is not None
