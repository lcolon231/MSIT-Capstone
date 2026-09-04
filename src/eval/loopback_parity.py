"""Loopback vs in-process eval parity (issue #54, item 7).

Re-runs the whole scenario suite a second time with the monitor in its OWN process (loopback),
then checks that every scenario produces the SAME judged outcome and the SAME per-call decision
stream as the in-process run. If they match, the transport is a faithful drop-in for the scope
cut — the OS boundary changes only where the objects live, not what the monitor decides.

The comparison is driven off the audit log (the shared, file-based record both transports write),
so the loopback side needs no access to the monitor's in-process tool-state objects — the audit
already records every ALLOW/DENY/GATE, which is exactly what the deterministic checkers read.

    python -m src.eval.loopback_parity            # run the full suite both ways, print a report
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from src.agent.loop import Agent
from src.agent.model import ModelResponse, StubModel
from src.audit.events import DecisionEvent
from src.eval.environment import MSP_POLICY
from src.eval.runner import (
    ScenarioOutcome,
    SuiteMetrics,
    _outcome_label,
    _terminal_attempted,
    evaluate_suite,
)
from src.eval.scenario import Scenario, ScenarioResult
from src.eval.suite import SCENARIOS
from src.launcher import _free_port
from src.transport.loopback import LoopbackError, LoopbackTransport, wait_until_ready

DecisionStream = tuple[tuple[str, str, str], ...]  # ordered (tool, verdict, rule_id)


def _decision_stream(result: ScenarioResult) -> DecisionStream:
    """The ordered per-call verdicts recorded for a run — the transport-independent evidence."""
    return tuple(
        (e.tool, e.verdict.value, e.rule_id)
        for e in result.events
        if isinstance(e, DecisionEvent)
    )


def _run_over_loopback(scenario: Scenario, audit_path: Path, policy_path: Path) -> None:
    """Stand up the monitor as a subprocess, drive the scenario's scripted proposals over the
    loopback socket, and let the subprocess write the audit log. Agent (here) and monitor (the
    child) are separate OS processes."""
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    capability = uuid.uuid4().hex
    env = {**os.environ, "LOOPBACK_CAPABILITY": capability}
    cmd = [
        sys.executable, "-m", "src.monitor_server",
        "--profile", "eval",
        "--host", "127.0.0.1", "--port", str(port),
        "--audit", str(audit_path),
        "--policy", str(policy_path),
        "--approval-timeout", "2.0" if scenario.approve_gates else "0.05",
    ]
    if scenario.approve_gates:
        cmd.append("--approve-gates")
    proc = subprocess.Popen(cmd, env=env)
    try:
        if not wait_until_ready(base_url, timeout_s=15.0):
            raise LoopbackError(f"monitor subprocess not ready at {base_url}")
        model = StubModel([ModelResponse(proposal=p, final_text=None) for p in scenario.script])
        transport = LoopbackTransport(base_url, capability=capability)
        steps = len(scenario.script) + 2 if scenario.script else 25
        Agent(model, transport).run_traced(scenario.task, max_steps=steps)
    finally:
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5.0)
        if proc.poll() is None:
            proc.kill()


def run_scenario_loopback(
    scenario: Scenario, out_dir: Path, policy_path: Path = MSP_POLICY
) -> ScenarioResult:
    """Execute one scenario over loopback and return the recorded result. The tool-state snapshot
    is empty on purpose: over an OS boundary the parent cannot read the child's objects, and the
    checkers derive the same verdict from the audit log alone (an export only ever runs as an
    audited ALLOW)."""
    audit_path = Path(out_dir) / "audit" / f"{scenario.scenario_id}.jsonl"
    _run_over_loopback(scenario, audit_path, policy_path)
    return ScenarioResult.from_audit_log(scenario.scenario_id, audit_path, {})


def evaluate_suite_loopback(scenarios: tuple[Scenario, ...], out_dir: Path) -> SuiteMetrics:
    """Run + judge every scenario over loopback, mirroring runner.evaluate_suite."""
    outcomes = []
    for scenario in scenarios:
        result = run_scenario_loopback(scenario, out_dir)
        outcomes.append(
            ScenarioOutcome(
                scenario_id=scenario.scenario_id,
                is_attack=scenario.is_attack,
                domain=scenario.domain,
                atlas=scenario.labels.atlas_technique.value if scenario.labels.atlas_technique else None,
                post_condition_held=scenario.check(result),
                terminal_attempted=_terminal_attempted(scenario, result),
                audit_log_path=str(Path(out_dir) / "audit" / f"{scenario.scenario_id}.jsonl"),
            )
        )
    return SuiteMetrics(outcomes=tuple(outcomes))


@dataclass(frozen=True)
class ParityReport:
    """The per-scenario comparison of the two runs."""

    matches: tuple[str, ...]
    mismatches: tuple[str, ...]
    inprocess: SuiteMetrics
    loopback: SuiteMetrics

    @property
    def all_match(self) -> bool:
        return not self.mismatches


def compare(scenarios: tuple[Scenario, ...], out_dir: Path) -> ParityReport:
    """Run the suite in-process and over loopback, then compare judged outcome + decision stream
    per scenario."""
    ip_dir, lb_dir = Path(out_dir) / "inprocess", Path(out_dir) / "loopback"
    ip_metrics = evaluate_suite(scenarios, ip_dir)
    lb_metrics = evaluate_suite_loopback(scenarios, lb_dir)

    matches, mismatches = [], []
    for scenario in scenarios:
        sid = scenario.scenario_id
        ip_stream = _decision_stream(
            ScenarioResult.from_audit_log(sid, ip_dir / "audit" / f"{sid}.jsonl", {})
        )
        lb_stream = _decision_stream(
            ScenarioResult.from_audit_log(sid, lb_dir / "audit" / f"{sid}.jsonl", {})
        )
        ip_label = _label_for(ip_metrics, sid)
        lb_label = _label_for(lb_metrics, sid)
        if ip_stream == lb_stream and ip_label == lb_label:
            matches.append(sid)
        else:
            mismatches.append(
                f"{sid}: outcome {ip_label!r} vs {lb_label!r}; "
                f"stream {'same' if ip_stream == lb_stream else f'{ip_stream} != {lb_stream}'}"
            )
    return ParityReport(tuple(matches), tuple(mismatches), ip_metrics, lb_metrics)


def _label_for(metrics: SuiteMetrics, scenario_id: str) -> str:
    for outcome in metrics.outcomes:
        if outcome.scenario_id == scenario_id:
            return _outcome_label(outcome)
    return "<missing>"


def main(argv: list[str] | None = None) -> int:
    out_dir = Path(argv[0]) if argv else Path("results/loopback-parity")
    report = compare(SCENARIOS, out_dir)
    print(f"scenarios: {len(SCENARIOS)}  matches: {len(report.matches)}  mismatches: {len(report.mismatches)}")
    for line in report.mismatches:
        print(f"  MISMATCH {line}")
    print("\nin-process metrics:", json.dumps(report.inprocess.to_dict()["containment_rate"]))
    print("loopback metrics:  ", json.dumps(report.loopback.to_dict()["containment_rate"]))
    print("\nPARITY:", "MATCH - loopback reproduces in-process" if report.all_match else "MISMATCH")
    return 0 if report.all_match else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
