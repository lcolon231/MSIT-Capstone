"""Loopback transport integration (issue #54, D11 PRIMARY).

Proves the loopback path is a real, working transport — not the old stub — and that it upholds
the enforcement guarantees over an actual socket:

  * the full kill chain is blocked with the agent and monitor in SEPARATE OS processes (the
    headline OS-isolation claim);
  * session creation requires the launcher-only bootstrap capability;
  * a bogus session and an unknown tool fail closed to a DENY result, never an exception.

The in-process behaviour is already covered by tests/monitor; here we assert the WIRE path
carries the same verdicts.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest

from src.agent.loop import Agent
from src.agent.model import ModelResponse, StubModel
from src.composition import build_monitor
from src.launcher import _loopback_transport, demo_script
from src.transport.contract import ResultStatus, SessionHandle, ToolCallProposal, Verdict
from src.transport.loopback import LoopbackError, LoopbackTransport, wait_until_ready
from src.transport.loopback_server import LoopbackServer

REPO_ROOT = Path(__file__).resolve().parents[1]
RMM = REPO_ROOT / "policies" / "rmm.yaml"


@contextmanager
def running_server(tmp_path: Path, capability: str | None = None) -> Iterator[LoopbackServer]:
    """A LoopbackServer bound to an ephemeral port, served on a background thread. Used for the
    wire-level checks that don't need a second OS process."""
    service = build_monitor(RMM, tmp_path / "audit.jsonl", approval_timeout_s=0.05)
    server = LoopbackServer(service, host="127.0.0.1", port=0, capability=capability)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert wait_until_ready(server.base_url), "server never became ready"
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


# --- the headline claim: kill chain blocked across two OS processes ------------------------


def test_kill_chain_blocked_with_agent_and_monitor_in_separate_processes(tmp_path: Path) -> None:
    audit = tmp_path / "loopback-audit.jsonl"
    model = StubModel(demo_script(), done_text="done")
    with _loopback_transport(RMM, audit) as transport:
        run = Agent(model, transport).run_traced("drain the account", max_steps=10)

    tools = [proposal.tool for proposal, _ in run.steps]
    assert tools == ["list_endpoints", "list_shares", "register_destination", "export_records"]

    # The first three recon/setup calls execute; the terminal exfil is DENIED by the sequence
    # engine — the same verdict as in-process, now carried over the loopback socket.
    statuses = [result.status for _, result in run.steps]
    assert statuses[:3] == [ResultStatus.EXECUTED] * 3
    export_result = run.steps[-1][1]
    assert export_result.status is ResultStatus.DENIED
    assert export_result.decision.verdict is Verdict.DENY
    assert audit.exists() and audit.read_text(encoding="utf-8").strip(), "monitor wrote no audit"


# --- capability + fail-closed behaviour over the wire --------------------------------------


def test_session_requires_bootstrap_capability(tmp_path: Path) -> None:
    with running_server(tmp_path, capability="s3cr3t-cap") as server:
        # No capability presented → the monitor refuses to mint a session.
        with pytest.raises(LoopbackError):
            LoopbackTransport(server.base_url).open_session()
        # Wrong capability → still refused.
        with pytest.raises(LoopbackError):
            LoopbackTransport(server.base_url, capability="wrong").open_session()
        # Correct capability → a session is issued.
        handle = LoopbackTransport(server.base_url, capability="s3cr3t-cap").open_session()
        assert handle.token


def test_unknown_session_fails_closed_to_deny(tmp_path: Path) -> None:
    with running_server(tmp_path) as server:
        transport = LoopbackTransport(server.base_url)
        # A forged/unknown session token is a normal DENY result, not a transport error.
        result = transport.dispatch(
            ToolCallProposal(tool="list_endpoints", args={}), SessionHandle(token="forged")
        )
        assert result.status is ResultStatus.DENIED
        assert result.decision.verdict is Verdict.DENY


def test_unknown_tool_fails_closed_to_deny(tmp_path: Path) -> None:
    with running_server(tmp_path) as server:
        transport = LoopbackTransport(server.base_url)
        session = transport.open_session()
        result = transport.dispatch(ToolCallProposal(tool="no_such_tool", args={}), session)
        assert result.status is ResultStatus.DENIED
        assert result.decision.verdict is Verdict.DENY


def test_unreachable_endpoint_raises_loopback_error() -> None:
    # Nothing is listening here; the client must surface a transport fault, not hang or crash.
    transport = LoopbackTransport("http://127.0.0.1:1", timeout=1.0)
    with pytest.raises(LoopbackError):
        transport.open_session()
