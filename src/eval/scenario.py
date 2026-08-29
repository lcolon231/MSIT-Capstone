"""Scenario schema + result (D13, D6) — the evaluation harness's data model.

Red-team scenarios are labelled with a **MITRE ATLAS technique** (primary, exactly one) and,
when adapted from STAC, an optional **Agent-SafetyBench failure mode** (secondary). Each scenario
carries a benign/attack tag and a **deterministic post-condition checker** (D6) — a pure function
of the recorded run (audit log + tool-state snapshot), never an LLM judge. The suite itself is
issue #18; the runner + metrics are #19. This file fixes the format and the result the checker
reads, so the same recorded run always yields the same verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping

from src.audit.events import AuditEvent
from src.audit.replay import replay


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
    """The recorded outcome of one scenario run, as the deterministic checker sees it: the
    replayed audit events plus a snapshot of the mock tool state (e.g. what was exported). It
    holds already-materialized data — no file handles, no clock — so a checker over it is pure."""

    scenario_id: str
    events: tuple[AuditEvent, ...] = ()
    tool_state: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_audit_log(
        cls, scenario_id: str, audit_log_path: str | Path, tool_state: Mapping[str, Any] | None = None
    ) -> "ScenarioResult":
        """Build a result by replaying the run's audit log once and capturing a tool-state
        snapshot. The replay/IO happens here; checkers stay pure over the materialized result."""
        events = tuple(replay(Path(audit_log_path)))
        return cls(scenario_id=scenario_id, events=events, tool_state=dict(tool_state or {}))


# A deterministic post-condition checker (D6): a pure function of the recorded ScenarioResult that
# returns True iff the scenario's post-condition holds (for an attack: the harmful effect
# escaped). No LLM, no I/O, no clock (spec.md §10, qa-redteam-plan.md T6.2).
PostConditionChecker = Callable[[ScenarioResult], bool]


@dataclass(frozen=True)
class Scenario:
    """One red-team or benign scenario."""

    scenario_id: str
    is_attack: bool
    labels: ScenarioLabels
    task: str  # the operator task text that drives the agent run
    check: PostConditionChecker  # binary escape verdict (D6); required for every scenario
