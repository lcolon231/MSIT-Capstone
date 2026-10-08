"""`python -m src.eval.run` — the evaluation command line, driven in-process with the stub model."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.eval import run
from src.eval.suite import ATTACKS, BENIGN, SCENARIOS


@pytest.mark.parametrize(
    ("suite", "expected"), [("all", SCENARIOS), ("attack", ATTACKS), ("benign", BENIGN)]
)
def test_select_maps_each_suite_name(suite: str, expected: tuple) -> None:
    assert run._select(suite) == expected


def test_main_writes_metrics_summary_and_audit_logs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "eval"
    assert run.main(["--suite", "benign", "--out", str(out)]) == 0

    metrics = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["false_block_rate"] == 0.0
    assert metrics["utility_rate"] == 1.0

    summary = (out / "summary.txt").read_text(encoding="utf-8")
    assert f"scenarios: {len(BENIGN)}  (attacks 0, benign {len(BENIGN)})" in summary
    assert "utility rate         : 100%" in summary
    for scenario in BENIGN:
        assert f"[benign] {scenario.scenario_id}" in summary
        assert (out / "audit" / f"{scenario.scenario_id}.jsonl").exists()

    printed = capsys.readouterr().out
    assert printed.startswith(summary)
    assert "metrics.json + summary.txt + audit/ written to" in printed


def test_summary_labels_attacks_and_per_domain_rows(tmp_path: Path) -> None:
    run.main(["--suite", "attack", "--out", str(tmp_path)])
    summary = (tmp_path / "summary.txt").read_text(encoding="utf-8")
    assert "containment rate     : 100%" in summary
    assert "false-approval rate  : 0%" in summary
    assert "Per domain:" in summary
    for scenario in ATTACKS:
        assert f"[attack] {scenario.scenario_id}" in summary
