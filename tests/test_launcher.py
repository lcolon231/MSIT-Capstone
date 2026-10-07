"""Trusted launcher (src/launcher.py) — composition of agent + monitor, without Ollama or sockets.

  * `build_model` picks the stub or Ollama client without contacting anything;
  * `main` over the in-process transport runs the scripted kill chain and the terminal export
    is DENY'd by the sequence layer;
  * `main --transport loopback` routes through `_loopback_transport` (faked here);
  * `_loopback_transport` fails closed when the monitor never becomes ready, and always tears
    the monitor process down (terminate → kill if it will not exit).

The real subprocess path is exercised by the integration suite.
"""

from __future__ import annotations

import contextlib
import subprocess
from pathlib import Path
from typing import Iterator

import pytest

import src.launcher as launcher
from src.agent.loop import AgentRun
from src.agent.model import OllamaModel, StubModel
from src.composition import build_monitor
from src.transport.contract import (
    DecisionSummary,
    ResultStatus,
    ToolCallProposal,
    ToolResult,
    Verdict,
)
from src.transport.inprocess import InProcessTransport
from src.transport.loopback import LoopbackError, LoopbackTransport

REPO_ROOT = Path(__file__).resolve().parents[1]
RMM = REPO_ROOT / "policies" / "rmm.yaml"


def test_build_model_stub_returns_scripted_stub() -> None:
    assert isinstance(launcher.build_model("stub", "m", "http://h"), StubModel)


def test_build_model_ollama_constructs_without_network() -> None:
    assert isinstance(launcher.build_model("ollama", "m", "http://h"), OllamaModel)


def test_demo_script_ends_with_export_to_just_registered_destination() -> None:
    script = launcher.demo_script()
    tools = [step.proposal.tool for step in script if step.proposal is not None]
    assert tools == ["list_endpoints", "list_shares", "register_destination", "export_records"]
    register, export = script[2].proposal, script[3].proposal
    assert register is not None and export is not None
    assert export.args["to"] == register.args["destination"]


def test_main_inprocess_blocks_terminal_export_at_sequence_layer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = launcher.main(
        ["--task", "t", "--policy", str(RMM), "--audit", str(tmp_path / "a.jsonl")]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "[4] export_records" in out
    assert "DENIED  [deny/seq.recon_register_exfil.terminal]" in out
    assert "final: stub demo complete" in out


def test_main_loopback_uses_loopback_transport_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    used: list[tuple[Path, Path]] = []

    @contextlib.contextmanager
    def fake(policy: Path, audit: Path) -> Iterator[InProcessTransport]:
        used.append((policy, audit))
        yield InProcessTransport(build_monitor(policy, audit))

    monkeypatch.setattr(launcher, "_loopback_transport", fake)
    audit = tmp_path / "a.jsonl"
    code = launcher.main(
        ["--task", "t", "--transport", "loopback", "--policy", str(RMM), "--audit", str(audit)]
    )
    assert code == 0
    assert used == [(RMM, audit)]
    assert "seq.recon_register_exfil.terminal" in capsys.readouterr().out


def test_print_run_with_no_steps_says_so(capsys: pytest.CaptureFixture[str]) -> None:
    launcher._print_run("t", AgentRun(final_text="done"))
    assert "(the agent proposed no tool calls)" in capsys.readouterr().out


def test_print_run_formats_each_step(capsys: pytest.CaptureFixture[str]) -> None:
    result = ToolResult(ResultStatus.EXECUTED, DecisionSummary(Verdict.ALLOW, "r.1", "ok"))
    launcher._print_run("t", AgentRun("done", ((ToolCallProposal("x", {"a": 1}), result),)))
    assert "[1] x(a=1) -> EXECUTED  [allow/r.1]" in capsys.readouterr().out


def test_free_port_returns_a_bindable_port() -> None:
    assert 0 < launcher._free_port() < 65536


# --- _loopback_transport lifecycle, with the subprocess faked ------------------------------


class FakeProc:
    def __init__(self, exits: bool) -> None:
        self.exits = exits
        self.terminated = self.killed = False
        self.argv: list[str] = []
        self.env: dict[str, str] = {}

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: float) -> int:
        if not self.exits:
            raise subprocess.TimeoutExpired("monitor", timeout)
        return 0

    def poll(self) -> int | None:
        return 0 if self.exits else None

    def kill(self) -> None:
        self.killed = True


def install_fake_popen(monkeypatch: pytest.MonkeyPatch, proc: FakeProc, ready: bool) -> None:
    def popen(argv: list[str], env: dict[str, str]) -> FakeProc:
        proc.argv, proc.env = argv, env
        return proc

    monkeypatch.setattr(launcher.subprocess, "Popen", popen)
    monkeypatch.setattr(launcher, "wait_until_ready", lambda url, timeout_s: ready)


def test_loopback_transport_not_ready_raises_and_terminates_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc = FakeProc(exits=True)
    install_fake_popen(monkeypatch, proc, ready=False)
    with pytest.raises(LoopbackError):
        with launcher._loopback_transport(RMM, tmp_path / "a.jsonl"):
            pytest.fail("must not yield a transport when the monitor is not ready")
    assert proc.terminated and not proc.killed


def test_loopback_transport_ready_yields_client_with_capability_shared_via_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc = FakeProc(exits=True)
    install_fake_popen(monkeypatch, proc, ready=True)
    with launcher._loopback_transport(RMM, tmp_path / "a.jsonl") as transport:
        assert isinstance(transport, LoopbackTransport)
        capability = proc.env["LOOPBACK_CAPABILITY"]
        assert transport._capability == capability
        assert len(capability) >= 32
    assert "src.monitor_server" in proc.argv
    assert proc.terminated


def test_loopback_transport_kills_process_that_ignores_terminate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc = FakeProc(exits=False)
    install_fake_popen(monkeypatch, proc, ready=True)
    with launcher._loopback_transport(RMM, tmp_path / "a.jsonl"):
        pass
    assert proc.terminated and proc.killed
