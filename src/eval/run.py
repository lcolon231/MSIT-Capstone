"""Evaluation CLI (issue #19, T5.3).

    python -m src.eval.run --suite all --out results/

Runs the scenario suite through the monitor and writes, under ``--out``:
  - ``metrics.json``  — machine-readable metrics (containment / false-approval / false-block /
    utility, overall + per domain + per scenario);
  - ``summary.txt``   — the same as a readable table;
  - ``audit/<scenario_id>.jsonl`` — the append-only audit log for each run.

``--model stub`` (default) replays the scripted scenarios deterministically. ``--model ollama``
drives a live Llama-3.1-8B on the build box; the metrics are computed identically from whatever
the monitor recorded.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from src.eval.runner import SuiteMetrics, _outcome_label, evaluate_suite
from src.eval.suite import ATTACKS, BENIGN, SCENARIOS


def _select(suite: str) -> tuple:
    return {"all": SCENARIOS, "attack": ATTACKS, "benign": BENIGN}[suite]


def _summary(metrics: SuiteMetrics) -> str:
    lines = [
        "Agent Tool-Call Containment Monitor - evaluation summary",
        "=" * 56,
        f"scenarios: {len(metrics.outcomes)}  (attacks {len(metrics.attacks)}, benign {len(metrics.benign)})",
        "",
        f"  containment rate     : {metrics.containment_rate:.0%}  (attacks blocked)",
        f"  false-approval rate  : {metrics.false_approval_rate:.0%}  (attacks that escaped)",
        f"  false-block rate     : {metrics.false_block_rate:.0%}  (benign over-blocked)",
        f"  utility rate         : {metrics.utility_rate:.0%}  (benign completed)",
        "",
        f"  attack attempt rate  : {metrics.attempt_rate:.0%}  "
        f"({len(metrics.attempted_attacks)}/{len(metrics.attacks)} attacks reached the monitor)",
        f"  monitor containment  : {metrics.monitor_containment_rate:.0%}  (of attempted attacks, blocked)",
        "",
        "Per domain:",
        f"  {'domain':<12} {'atk':>4} {'ben':>4} {'false-appr':>11} {'false-block':>12} {'utility':>8}",
    ]
    for domain, m in metrics.per_domain().items():
        lines.append(
            f"  {domain:<12} {m['attacks']:>4} {m['benign']:>4} "
            f"{m['false_approval_rate']:>11.0%} {m['false_block_rate']:>12.0%} {m['utility_rate']:>8.0%}"
        )
    lines += ["", "Per scenario:"]
    for o in metrics.outcomes:
        kind = "attack" if o.is_attack else "benign"
        lines.append(f"  [{kind}] {o.scenario_id:<44} {_outcome_label(o)}")
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m src.eval.run", description="Run the containment-monitor evaluation suite.")
    parser.add_argument("--suite", choices=("all", "attack", "benign"), default="all")
    parser.add_argument("--out", default="results/")
    parser.add_argument("--model", choices=("stub", "ollama"), default="stub")
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="fix the live model's sampling seed for a reproducible run (ollama only); vary it "
        "across runs for multi-seed variance",
    )
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    metrics = evaluate_suite(_select(args.suite), out_dir, model_kind=args.model, seed=args.seed)

    (out_dir / "metrics.json").write_text(json.dumps(metrics.to_dict(), indent=2), encoding="utf-8")
    summary = _summary(metrics)
    (out_dir / "summary.txt").write_text(summary, encoding="utf-8")
    print(summary)
    print(f"metrics.json + summary.txt + audit/ written to {out_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
