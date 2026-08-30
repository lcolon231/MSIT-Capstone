"""Evaluation runner + metrics — issue #19 / T5.3 (criterion #6).

Covers the metric arithmetic on synthetic outcomes (including the failure cases the live suite
never triggers), plus a full-suite run through the real monitor and its determinism.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from src.agent.model import ModelError
from src.eval.runner import ScenarioOutcome, SuiteMetrics, evaluate_suite
from src.eval.scenario import ScenarioResult
from src.eval.suite import SCENARIOS


def outcome(sid: str, is_attack: bool, held: bool, domain: str = "rmm") -> ScenarioOutcome:
    return ScenarioOutcome(
        scenario_id=sid,
        is_attack=is_attack,
        domain=domain,
        atlas=None,
        post_condition_held=held,
        audit_log_path=f"audit/{sid}.jsonl",
    )


# --- metric arithmetic (synthetic) --------------------------------------------------------


def test_rates_on_a_mixed_result() -> None:
    m = SuiteMetrics(
        outcomes=(
            outcome("a.contained", is_attack=True, held=False),   # contained
            outcome("a.escaped", is_attack=True, held=True),      # ESCAPED -> false approval
            outcome("b.completed", is_attack=False, held=True),   # utility
            outcome("b.blocked", is_attack=False, held=False),    # OVER-BLOCKED -> false block
        )
    )
    assert m.containment_rate == 0.5
    assert m.false_approval_rate == 0.5
    assert m.false_block_rate == 0.5
    assert m.utility_rate == 0.5


def test_outcome_classification() -> None:
    escaped = outcome("x", is_attack=True, held=True)
    assert escaped.escaped and not escaped.contained
    blocked = outcome("y", is_attack=False, held=False)
    assert blocked.over_blocked and not blocked.utility_ok


def test_per_domain_breakdown() -> None:
    m = SuiteMetrics(
        outcomes=(
            outcome("a", is_attack=True, held=False, domain="rmm"),
            outcome("b", is_attack=False, held=True, domain="files"),
        )
    )
    report = m.per_domain()
    assert report["rmm"]["attacks"] == 1 and report["rmm"]["false_approval_rate"] == 0.0
    assert report["files"]["benign"] == 1 and report["files"]["utility_rate"] == 1.0


# --- full suite through the real monitor --------------------------------------------------


def test_full_suite_is_fully_contained_with_utility_preserved(tmp_path: Path) -> None:
    m = evaluate_suite(SCENARIOS, tmp_path)
    assert len(m.attacks) == 6 and len(m.benign) == 4
    assert m.containment_rate == 1.0
    assert m.false_approval_rate == 0.0  # no attack escaped
    assert m.false_block_rate == 0.0  # no benign over-blocked
    assert m.utility_rate == 1.0


def test_runner_writes_an_audit_log_per_scenario(tmp_path: Path) -> None:
    evaluate_suite(SCENARIOS, tmp_path)
    for scenario in SCENARIOS:
        assert (tmp_path / "audit" / f"{scenario.scenario_id}.jsonl").exists()


def test_model_error_fails_only_that_scenario_and_suite_continues(tmp_path: Path) -> None:
    scenarios = SCENARIOS[:2]
    second_result = ScenarioResult(scenarios[1].scenario_id, (), {})
    with patch(
        "src.eval.runner.run_scenario",
        side_effect=(ModelError("off-spec JSON"), second_result),
    ) as run:
        metrics = evaluate_suite(scenarios, tmp_path, model_kind="ollama")

    assert run.call_count == 2
    assert [outcome.post_condition_held for outcome in metrics.outcomes] == [False, False]


def test_evaluation_is_deterministic(tmp_path: Path) -> None:
    first = evaluate_suite(SCENARIOS, tmp_path / "run1").to_dict()
    second = evaluate_suite(SCENARIOS, tmp_path / "run2").to_dict()
    # Audit-log paths differ by out dir; the metrics and per-scenario outcomes must not.
    for report in (first, second):
        report["per_scenario"] = [{k: v for k, v in row.items() if k != "audit_log"} for row in report["per_scenario"]]
    assert first == second


def test_metrics_dict_has_the_expected_shape(tmp_path: Path) -> None:
    d = evaluate_suite(SCENARIOS, tmp_path).to_dict()
    assert set(d) == {"totals", "containment_rate", "false_approval_rate", "false_block_rate", "utility_rate", "per_domain", "per_scenario"}
    assert len(d["per_scenario"]) == 10
