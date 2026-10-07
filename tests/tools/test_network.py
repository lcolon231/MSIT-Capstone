"""Network mock domain (issue #16) — no sockets, no egress; activity is only recorded in-process."""

from __future__ import annotations

import socket

import pytest

from src.tools.base import ToolRegistry
from src.tools.network import FetchUrl, NetworkLog, SendNetwork, register_network


@pytest.fixture(autouse=True)
def no_real_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any attempt to open a real socket fails the test."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("mock network tool attempted a real socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def test_fetch_url_returns_canned_response_and_records_fetch() -> None:
    log = NetworkLog()
    result = FetchUrl(log).execute({"url": "https://example.com"}, "c1")
    assert result == {
        "url": "https://example.com",
        "status": 200,
        "bytes": len("mock-response-body"),
    }
    assert log.fetched == [("c1", "https://example.com")]
    assert log.sent == []


def test_fetch_url_missing_url_is_recorded_as_empty() -> None:
    log = NetworkLog()
    assert FetchUrl(log).execute({}, "c1")["url"] == ""


def test_send_network_records_principal_dest_and_size() -> None:
    log = NetworkLog()
    result = SendNetwork(log).execute({"dest": "10.0.0.9", "payload": "hello"}, "c1")
    assert result == {"sent_to": "10.0.0.9", "bytes": 5}
    assert log.sent == [("c1", "10.0.0.9", 5)]


def test_send_network_does_not_echo_payload_back() -> None:
    result = SendNetwork(NetworkLog()).execute({"dest": "d", "payload": "PHI-123"}, "c1")
    assert "PHI-123" not in str(result)


def test_send_network_principal_comes_from_monitor_not_args() -> None:
    log = NetworkLog()
    SendNetwork(log).execute({"dest": "d", "payload": "", "principal": "c2"}, "c1")
    assert log.sent[0][0] == "c1"


def test_register_network_registers_fetch_and_send() -> None:
    registry = ToolRegistry()
    register_network(registry, NetworkLog())
    assert [spec.name for spec in registry.specs()] == ["fetch_url", "send_network"]
