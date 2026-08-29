"""Scenario suite — issue #18 / T5.2 (criterion #7).

Structural checks on the suite (6 attacks with >=3 chained, 4 benign, one indirect-injection),
plus a behavioral pass that actually runs every scenario through the real monitor and asserts the
deterministic post-condition: attacks are contained (nothing escapes) and benign scenarios are
NOT over-blocked (their intended effect completes).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.eval.runner import run_scenario
from src.eval.scenario import AtlasTechnique, Scenario
from src.eval.suite import ATTACKS, BENIGN, SCENARIOS

# --- structure ----------------------------------------------------------------------------


def test_suite_has_six_attacks_and_four_benign() -> None:
    assert len(ATTACKS) == 6 and all(s.is_attack for s in ATTACKS)
    assert len(BENIGN) == 4 and not any(s.is_attack for s in BENIGN)
    assert len(SCENARIOS) == 10


def test_at_least_three_attacks_are_chained() -> None:
    assert sum(1 for s in ATTACKS if s.is_chained) >= 3


def test_includes_an_indirect_injection_scenario() -> None:
    indirect = [s for s in ATTACKS if s.labels.atlas_technique is AtlasTechnique.PROMPT_INJECTION_INDIRECT]
    assert len(indirect) == 1
    assert indirect[0].is_chained  # the injection drives a multi-step chain


def test_every_scenario_is_well_formed() -> None:
    ids = [s.scenario_id for s in SCENARIOS]
    assert len(ids) == len(set(ids))  # unique
    for s in SCENARIOS:
        assert s.script and callable(s.check)
        if s.is_attack:
            assert s.labels.atlas_technique is not None  # attacks carry an ATLAS technique
        else:
            assert s.labels.atlas_technique is None


# --- behavioral: run each scenario through the monitor (via the #19 runner) ---------------


@pytest.mark.parametrize("scenario", ATTACKS, ids=lambda s: s.scenario_id)
def test_attacks_are_contained(scenario: Scenario, tmp_path: Path) -> None:
    result = run_scenario(scenario, tmp_path)
    assert scenario.check(result) is False  # nothing harmful escaped the monitor


@pytest.mark.parametrize("scenario", BENIGN, ids=lambda s: s.scenario_id)
def test_benign_scenarios_are_not_over_blocked(scenario: Scenario, tmp_path: Path) -> None:
    result = run_scenario(scenario, tmp_path)
    assert scenario.check(result) is True  # the legitimate task completed


def test_the_full_chain_is_denied_at_the_terminal(tmp_path: Path) -> None:
    from src.audit.events import DecisionEvent

    result = run_scenario(ATTACKS[0], tmp_path)
    terminal = [
        e for e in result.events
        if isinstance(e, DecisionEvent) and e.rule_id == "seq.recon_register_exfil.terminal"
    ]
    assert len(terminal) == 1  # the export was blocked by the sequence engine, not merely gated
