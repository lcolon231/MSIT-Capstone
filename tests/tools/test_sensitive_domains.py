"""Files / network / credentials mock domains — issue #16 (T4.4).

Each domain runs over in-process state with no real egress and offers benign ALLOW operations
alongside its GATE-class operation. These are the tool-level unit tests; end-to-end GATE routing
and ALLOW execution through the service live in tests/monitor/test_gate_classes.py.
"""

from __future__ import annotations

from src.tools.base import ToolRegistry
from src.tools.credentials import (
    AccessCredential,
    CredentialStore,
    ListCredentials,
    register_credentials,
)
from src.tools.files import DeleteFile, FileStore, ListFiles, ReadFile, register_files
from src.tools.network import FetchUrl, NetworkLog, SendNetwork, register_network

# --- files --------------------------------------------------------------------------------


def test_list_files_returns_sorted_paths() -> None:
    store = FileStore(files={"client-1": {"/b": "y", "/a": "x"}})
    assert ListFiles(store).execute({}, "client-1") == {"paths": ["/a", "/b"]}


def test_read_file_returns_content_or_absent() -> None:
    store = FileStore(files={"client-1": {"/a": "hello"}})
    assert ReadFile(store).execute({"path": "/a"}, "client-1") == {"path": "/a", "present": True, "content": "hello"}
    assert ReadFile(store).execute({"path": "/missing"}, "client-1")["present"] is False


def test_delete_file_removes_existing_path() -> None:
    store = FileStore(files={"client-1": {"/a": "x", "/b": "y"}})
    assert DeleteFile(store).execute({"path": "/a"}, "client-1") == {"deleted": "/a", "existed": True}
    assert list(store.files["client-1"]) == ["/b"]


def test_delete_missing_file_is_not_an_error() -> None:
    assert DeleteFile(FileStore()).execute({"path": "/x"}, "client-1")["existed"] is False


# --- network ------------------------------------------------------------------------------


def test_fetch_url_is_read_only_and_records_no_egress() -> None:
    log = NetworkLog()
    result = FetchUrl(log).execute({"url": "http://mock/data"}, "client-1")
    assert result["url"] == "http://mock/data" and result["status"] == 200
    assert log.fetched == [("client-1", "http://mock/data")]
    assert log.sent == []  # a fetch never sends


def test_send_network_records_bytes_without_egress() -> None:
    log = NetworkLog()
    result = SendNetwork(log).execute({"dest": "10.0.0.1", "payload": "hello"}, "client-1")
    assert result == {"sent_to": "10.0.0.1", "bytes": 5}
    assert log.sent == [("client-1", "10.0.0.1", 5)]


# --- credentials --------------------------------------------------------------------------


def test_list_credentials_returns_names_only() -> None:
    store = CredentialStore(secrets={"db": "s3cr3t", "api": "k3y"})
    result = ListCredentials(store).execute({}, "client-1")
    assert result == {"names": ["api", "db"]}
    assert "s3cr3t" not in str(result) and "k3y" not in str(result)  # values never listed


def test_access_credential_never_returns_the_value() -> None:
    store = CredentialStore(secrets={"db": "s3cr3t"})
    result = AccessCredential(store).execute({"name": "db"}, "client-1")
    assert result == {"accessed": "db", "present": True}
    assert "s3cr3t" not in str(result)
    assert store.accesses == [("client-1", "db")]


# --- registration -------------------------------------------------------------------------


def test_register_helpers_populate_all_domain_tools() -> None:
    registry = ToolRegistry()
    register_files(registry, FileStore())
    register_network(registry, NetworkLog())
    register_credentials(registry, CredentialStore())
    for name in (
        "list_files",
        "read_file",
        "delete_file",
        "fetch_url",
        "send_network",
        "list_credentials",
        "access_credential",
    ):
        assert registry.get(name) is not None
