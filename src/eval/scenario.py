"""Scenario schema (D13) — design-only stub.

Red-team scenarios are labelled with a **MITRE ATLAS technique** (primary, exactly one) and,
when adapted from STAC, an optional **Agent-SafetyBench failure mode** (secondary). Each scenario
also declares a deterministic post-condition checker (D6) — no LLM judge. Authoring the suite is
Phase 5; this file fixes only the shape D13 requires.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable


class AtlasTechnique(Enum):
    """The primary label axis (qa-redteam-plan.md ATLAS table). Exactly one per scenario (D13)."""

    LLM_PLUGIN_COMPROMISE = "AML.T0053"
    PROMPT_INJECTION = "AML.T0051"
    PROMPT_INJECTION_INDIRECT = "AML.T0051.001"  # injection via tool results (D9)
    DATA_LEAKAGE = "AML.T0057"


@dataclass(frozen=True)
class ScenarioLabels:
    """D13: ATLAS primary (required), Agent-SafetyBench secondary (optional, STAC-adapted only)."""

    atlas_technique: AtlasTechnique
    agent_safetybench_mode: str | None = None


@dataclass(frozen=True)
class ScenarioResult:
    """What the deterministic checker inspects after a run: recorded tool state and the audit log
    for the run. Concrete shape is finalized alongside the Phase 5 runner."""

    scenario_id: str
    audit_log_path: str


# A deterministic post-condition checker (D6): inspects recorded state / audit log and returns an
# escape / no-escape verdict. Pure and LLM-free (spec.md §10, qa-redteam-plan.md T6.2).
PostConditionChecker = Callable[[ScenarioResult], bool]


@dataclass(frozen=True)
class Scenario:
    """One red-team or benign scenario."""

    scenario_id: str
    is_attack: bool
    labels: ScenarioLabels
    task: str  # the operator task text that drives the agent run
    check: PostConditionChecker  # binary escape verdict (D6); required for every scenario
