"""RMM mock domain tools — issue #11 / T3.2 (healthcare-MSP domain).

The five tools operate over one in-process `EndpointState`, keyed by the monitor-resolved
principal (the managed client). No real endpoints, no egress. Identity comes from the passed
`principal`, never from args.
"""

from __future__ import annotations

from src.tools.base import ToolRegistry
from src.tools.rmm import (
    EndpointState,
    ExportRecords,
    ListEndpoints,
    ListShares,
    RegisterDestination,
    register_rmm,
    rmm_tools,
)


def test_list_endpoints_reads_the_client_environment() -> None:
    state = EndpointState(endpoints={"client-1": ["ep-2", "ep-1"]})
    assert ListEndpoints(state).execute({}, "client-1") == {"endpoints": ["ep-1", "ep-2"]}


def test_list_endpoints_unknown_client_is_empty_not_error() -> None:
    assert ListEndpoints(EndpointState()).execute({}, "nobody") == {"endpoints": []}


def test_list_shares_returns_a_sorted_copy() -> None:
    state = EndpointState(shares={"client-1": ["billing", "patient-records"]})
    result = ListShares(state).execute({}, "client-1")
    assert result == {"shares": ["billing", "patient-records"]}
    result["shares"].append("mutated")
    assert state.shares["client-1"] == ["billing", "patient-records"]  # internal store untouched


def test_register_destination_appends_new_and_is_idempotent() -> None:
    state = EndpointState()
    RegisterDestination(state).execute({"destination": "dropbox"}, "client-1")
    RegisterDestination(state).execute({"destination": "dropbox"}, "client-1")  # dup -> no re-add
    assert state.destinations["client-1"] == ["dropbox"]


def test_export_records_records_the_export_without_egress() -> None:
    state = EndpointState()
    result = ExportRecords(state).execute({"to": "dropbox", "count": 500}, "client-1")
    assert result == {"exported": 500, "to": "dropbox"}
    assert state.exported == [("client-1", "dropbox", 500)]


def test_tools_share_one_state_across_the_domain() -> None:
    state = EndpointState(endpoints={"client-1": ["ep-1"]})
    list_endpoints, list_shares, register, _export, _disable = rmm_tools(state)
    register.execute({"destination": "dropbox"}, "client-1")
    assert list_endpoints.execute({}, "client-1") == {"endpoints": ["ep-1"]}
    assert list_shares.execute({}, "client-1") == {"shares": []}
    assert state.destinations["client-1"] == ["dropbox"]


def test_register_rmm_populates_the_registry() -> None:
    registry = ToolRegistry()
    register_rmm(registry, EndpointState())
    for name in (
        "list_endpoints",
        "list_shares",
        "register_destination",
        "export_records",
        "disable_logging",
    ):
        assert registry.get(name) is not None
    assert registry.get("no_such_tool") is None
