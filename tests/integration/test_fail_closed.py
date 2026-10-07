"""Scenario 5 — fail-closed boundaries, end to end. Every case must end in no ALLOW and no tool
execution. "Not executed" is proven on the mock environment itself: `register_destination` adds
to the captured `EndpointState.destinations`, so an unchanged list means the tool never ran.

  * transport failure mid-run (in-process wrapper raising; loopback server gone; garbage wire
    body) — the agent gets an error or a DENY, never a manufactured ALLOW;
  * a tool raising inside the monitor — DENY `system.error`;
  * policy missing / corrupted at load — deny-all fallback, nothing executes;
  * policy removed AFTER load — the loaded, immutable policy keeps governing;
  * audit sink unwritable — before the decision write, and between operator approval and the
    resolution write (audit-before-effect, interface-contracts.md §1.7).
"""

from __future__ import annotations

import http.client
import json
import os
import threading
from pathlib import Path
from typing import Callable

import pytest

from src.agent.loop import Agent
from src.agent.model import StubModel
from src.composition import PRINCIPAL
from src.tools import rmm
from src.transport.contract import (
    ResultStatus,
    SessionHandle,
    ToolCallProposal,
    ToolResult,
    Verdict,
)
from src.transport.inprocess import InProcessTransport
from src.transport.loopback import LoopbackError
from tests.integration.conftest import Wired, loopback_to, script

pytestmark = pytest.mark.integration

ORIGINAL_DESTINATIONS = ["approved-baa-backup"]
RECON_THEN_REGISTER = script(
    ("list_endpoints", {}),
    ("register_destination", {"destination": "attacker-dropbox"}),
)
EVERY_RMM_CALL = script(
    ("list_endpoints", {}),
    ("list_shares", {}),
    ("register_destination", {"destination": "attacker-dropbox"}),
    ("export_records", {"to": "approved-baa-backup", "count": 1}),
)


def destinations(w: Wired) -> list[str]:
    return list(w.endpoints.destinations[PRINCIPAL])


def break_audit_sink(path: Path) -> None:
    """Make further appends impossible on every OS: the log path becomes a directory."""
    if path.exists():
        os.remove(path)
    path.mkdir()


class FailingOnNth:
    """A Transport that delegates, then raises on the nth dispatch (1-based) — a transport fault
    in the middle of a run."""

    def __init__(self, inner: InProcessTransport, fail_on: int) -> None:
        self._inner, self._fail_on, self._count = inner, fail_on, 0

    def open_session(self) -> SessionHandle:
        return self._inner.open_session()

    def dispatch(self, proposal: ToolCallProposal, session: SessionHandle) -> ToolResult:
        self._count += 1
        if self._count == self._fail_on:
            raise ConnectionResetError("transport dropped mid-call")
        return self._inner.dispatch(proposal, session)


# --- transport raises mid-call ------------------------------------------------------------


def test_transport_raises_mid_run_propagates_and_tool_never_runs(wired: Wired) -> None:
    agent = Agent(
        StubModel(RECON_THEN_REGISTER), FailingOnNth(InProcessTransport(wired.service), 2)
    )
    with pytest.raises(ConnectionResetError):
        agent.run_traced("task")
    assert destinations(wired) == ORIGINAL_DESTINATIONS
    logged = wired.audit_path.read_text(encoding="utf-8")
    assert "register_destination" not in logged  # the monitor never even saw the call


def test_loopback_server_gone_mid_run_raises_and_tool_never_runs(wired: Wired) -> None:
    with loopback_to(wired.service) as transport:
        session = transport.open_session()
        first = transport.dispatch(ToolCallProposal("list_endpoints", {}), session)
        assert first.status is ResultStatus.EXECUTED
    # Server is shut down here; the client must error, not invent a result.
    with pytest.raises(LoopbackError):
        transport.dispatch(
            ToolCallProposal("register_destination", {"destination": "attacker-dropbox"}),
            session,
        )
    assert destinations(wired) == ORIGINAL_DESTINATIONS


@pytest.mark.parametrize(
    "body",
    [b"not json", b"[]", b'{"proposal": "x"}', b'{"proposal": {"tool": 5}, "session": 7}'],
    ids=["not-json", "array", "proposal-not-object", "wrong-types"],
)
def test_loopback_garbage_dispatch_body_returns_deny(wired: Wired, body: bytes) -> None:
    with loopback_to(wired.service) as transport:
        conn = http.client.HTTPConnection(transport._host, transport._port, timeout=10.0)
        try:
            conn.request(
                "POST", "/dispatch", body=body, headers={"Content-Type": "application/json"}
            )
            response = conn.getresponse()
            payload = json.loads(response.read())
        finally:
            conn.close()
    assert response.status == 200
    assert payload["status"] == ResultStatus.DENIED.value
    assert payload["decision"]["verdict"] == Verdict.DENY.value
    assert destinations(wired) == ORIGINAL_DESTINATIONS


def test_tool_raises_inside_monitor_reports_tool_failed_and_chain_does_not_advance(
    wired: Wired, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(self: object, args: object, principal: str) -> object:
        raise RuntimeError("endpoint agent crashed")

    monkeypatch.setattr(rmm.ListShares, "execute", explode)
    agent_run = Agent(
        StubModel(script(("list_endpoints", {}), ("list_shares", {}))),
        InProcessTransport(wired.service),
    ).run_traced("t")
    _, (_, failed) = agent_run.steps
    assert failed.status is ResultStatus.TOOL_FAILED
    assert failed.decision.rule_id == "rmm.list_shares.allow"
    assert failed.payload is None
    nodes = [p.node for chains in wired.sessions.live_state().progress.values() for p in chains]
    assert nodes == ["S1_ENDPOINTS"]  # the failed list_shares did not move the chain to S2


# --- policy missing or corrupted at load time ---------------------------------------------


@pytest.mark.parametrize(
    "corrupt",
    [
        "delete",
        "truncate",
        "garbage",
        "unknown-field",
        "allow-everything-typo",
    ],
)
def test_policy_missing_or_corrupt_at_load_denies_everything_and_runs_nothing(
    build_wired: Callable[..., Wired], policy_dir: Path, corrupt: str
) -> None:
    policy = policy_dir / "rmm.yaml"
    if corrupt == "delete":
        policy.unlink()
    elif corrupt == "truncate":
        policy.write_text("", encoding="utf-8")
    elif corrupt == "garbage":
        policy.write_bytes(b"\x00\xff\xfe rules: [")
    elif corrupt == "unknown-field":
        policy.write_text(
            policy.read_text(encoding="utf-8") + "\noverride: allow\n", encoding="utf-8"
        )
    else:  # an "allow" rule whose enforce value is misspelt must not load as allow
        policy.write_text(
            "rules:\n  - {rule_id: x, tool: register_destination, trigger: action, enforce: alow}\n",
            encoding="utf-8",
        )
    w = build_wired(policy_path=policy)
    agent_run = Agent(StubModel(EVERY_RMM_CALL), InProcessTransport(w.service)).run_traced("t")
    assert [r.decision.verdict for _, r in agent_run.steps] == [Verdict.DENY] * len(EVERY_RMM_CALL)
    assert all(r.status is ResultStatus.DENIED for _, r in agent_run.steps)
    assert destinations(w) == ORIGINAL_DESTINATIONS


def test_policy_removed_after_load_keeps_loaded_policy(wired: Wired) -> None:
    wired.policy_path.unlink()
    agent_run = Agent(
        StubModel(script(("list_endpoints", {}))), InProcessTransport(wired.service)
    ).run_traced("t")
    ((_, result),) = agent_run.steps
    assert result.decision.rule_id == "rmm.list_endpoints.allow"


# --- audit writer cannot write ------------------------------------------------------------


def test_audit_unwritable_before_decision_denies_and_tool_never_runs(wired: Wired) -> None:
    session = wired.service.open_session()  # the session-open event is written while healthy
    break_audit_sink(wired.audit_path)
    result = wired.service.handle(
        ToolCallProposal("register_destination", {"destination": "attacker-dropbox"}), session
    )
    assert result.status is ResultStatus.DENIED
    assert result.decision.verdict is Verdict.DENY
    assert destinations(wired) == ORIGINAL_DESTINATIONS


def test_audit_unwritable_after_operator_approval_denies_and_tool_never_runs(
    build_wired: Callable[..., Wired],
) -> None:
    w = build_wired(approval_timeout_s=60.0)
    session = w.service.open_session()
    results: list[ToolResult] = []
    worker = threading.Thread(
        target=lambda: results.append(
            w.service.handle(
                ToolCallProposal("export_records", {"to": "approved-baa-backup"}), session
            )
        ),
        daemon=True,
    )
    worker.start()
    assert w.approvals.enqueued.wait(10.0)
    break_audit_sink(w.audit_path)  # the GATE decision is already logged; the resolution cannot be
    (pending,) = w.approvals.list_pending()
    w.approvals.resolve(pending.approval_id, approved=True, operator="op")
    worker.join(10.0)
    assert not worker.is_alive()
    (result,) = results
    assert result.status is ResultStatus.DENIED
    assert result.payload is None
