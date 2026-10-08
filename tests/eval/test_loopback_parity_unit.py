"""Loopback parity logic without real subprocesses.

The end-to-end comparison is in test_loopback_parity.py (integration). These pin the parts that
run never exercises when parity holds: the mismatch report, the exit codes of `main`, and the
subprocess lifecycle when the monitor never becomes ready or ignores terminate.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from src.eval import loopback_parity as parity
from src.eval.runner import SuiteMetrics, evaluate_suite
from src.eval.suite import SCENARIOS
from src.transport.loopback import LoopbackError

_ONE = tuple(s for s in SCENARIOS if s.scenario_id == "attack.exfil_full_chain")


def _inprocess_as_loopback(monkeypatch: pytest.MonkeyPatch, tamper: bool) -> None:
    """Stand in for the loopback run with a second in-process run; optionally drop its last
    decision so the two decision streams differ."""

    def fake(scenarios: tuple, out_dir: Path) -> SuiteMetrics:
        metrics = evaluate_suite(scenarios, out_dir)
        if tamper:
            log = Path(out_dir) / "audit" / f"{scenarios[0].scenario_id}.jsonl"
            lines = log.read_text(encoding="utf-8").splitlines()
            last = max(i for i, line in enumerate(lines) if '"type":"decision"' in line)
            log.write_text("\n".join(lines[:last] + lines[last + 1 :]) + "\n", encoding="utf-8")
        return metrics

    monkeypatch.setattr(parity, "evaluate_suite_loopback", fake)


def test_compare_reports_a_match_when_streams_agree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _inprocess_as_loopback(monkeypatch, tamper=False)
    report = parity.compare(_ONE, tmp_path)
    assert report.all_match and report.matches == ("attack.exfil_full_chain",)


def test_compare_reports_a_diverging_decision_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _inprocess_as_loopback(monkeypatch, tamper=True)
    report = parity.compare(_ONE, tmp_path)
    assert not report.all_match
    (line,) = report.mismatches
    assert line.startswith("attack.exfil_full_chain: outcome ")
    assert " != " in line  # the two streams are printed side by side


def test_label_for_an_unknown_scenario_is_missing() -> None:
    assert parity._label_for(SuiteMetrics(outcomes=()), "nope") == "<missing>"


def _report(mismatches: tuple[str, ...]) -> parity.ParityReport:
    empty = SuiteMetrics(outcomes=())
    return parity.ParityReport(("a",), mismatches, empty, empty)


def test_main_exits_zero_on_parity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(parity, "compare", lambda scenarios, out: _report(()))
    assert parity.main([str(tmp_path)]) == 0
    assert "PARITY: MATCH" in capsys.readouterr().out


def test_main_exits_one_and_lists_mismatches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(parity, "compare", lambda scenarios, out: _report(("x: differs",)))
    assert parity.main([str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "MISMATCH x: differs" in out
    assert "PARITY: MISMATCH" in out


def test_main_defaults_its_output_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Path] = []
    monkeypatch.setattr(parity, "compare", lambda scenarios, out: seen.append(out) or _report(()))
    parity.main(None)
    assert seen == [Path("results/loopback-parity")]


class _Proc:
    def __init__(self, exits: bool) -> None:
        self.exits, self.terminated, self.killed = exits, False, False

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


def _fake_spawn(monkeypatch: pytest.MonkeyPatch, proc: _Proc, ready: bool) -> list[list[str]]:
    commands: list[list[str]] = []

    def popen(cmd: list[str], env: dict[str, str]) -> _Proc:
        commands.append(cmd)
        return proc

    monkeypatch.setattr(parity.subprocess, "Popen", popen)
    monkeypatch.setattr(parity, "wait_until_ready", lambda url, timeout_s: ready)
    return commands


def test_monitor_that_never_becomes_ready_raises_and_is_terminated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc = _Proc(exits=True)
    _fake_spawn(monkeypatch, proc, ready=False)
    with pytest.raises(LoopbackError, match="not ready"):
        parity._run_over_loopback(_ONE[0], tmp_path / "a.jsonl", parity.MSP_POLICY)
    assert proc.terminated and not proc.killed


def test_monitor_that_ignores_terminate_is_killed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc = _Proc(exits=False)
    _fake_spawn(monkeypatch, proc, ready=False)
    with pytest.raises(LoopbackError):
        parity._run_over_loopback(_ONE[0], tmp_path / "a.jsonl", parity.MSP_POLICY)
    assert proc.terminated and proc.killed


def test_gate_approving_scenarios_start_the_monitor_with_auto_approve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    approving = next(s for s in SCENARIOS if s.approve_gates)
    commands = _fake_spawn(monkeypatch, _Proc(exits=True), ready=False)
    with pytest.raises(LoopbackError):
        parity._run_over_loopback(approving, tmp_path / "a.jsonl", parity.MSP_POLICY)
    (cmd,) = commands
    assert "--approve-gates" in cmd
    assert cmd[cmd.index("--approval-timeout") + 1] == "2.0"
