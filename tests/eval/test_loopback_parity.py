"""Loopback eval parity (issue #54, item 7) — a fast subset.

The full-suite comparison lives in `src.eval.loopback_parity.main`; this test pins the guarantee
with a representative pair (a chained exfil attack and a gated benign export) so a regression in
the wire path — a lost verdict, a dropped gate — fails CI without spawning ten subprocesses.
"""

from __future__ import annotations

from pathlib import Path

from src.eval.loopback_parity import compare
from src.eval.suite import SCENARIOS

_SUBSET_IDS = {"attack.exfil_full_chain", "benign.approved_export_to_baa_destination"}
_SUBSET = tuple(s for s in SCENARIOS if s.scenario_id in _SUBSET_IDS)


def test_loopback_matches_inprocess_on_representative_subset(tmp_path: Path) -> None:
    assert len(_SUBSET) == len(_SUBSET_IDS), "expected subset scenarios not found in the suite"
    report = compare(_SUBSET, tmp_path)
    assert report.all_match, f"loopback diverged from in-process: {report.mismatches}"
    # Both transports must reach the same aggregate verdicts, not merely the same per-scenario ones.
    assert report.inprocess.containment_rate == report.loopback.containment_rate
    assert report.inprocess.utility_rate == report.loopback.utility_rate
