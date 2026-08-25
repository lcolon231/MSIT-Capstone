"""Replay — reconstruct decisions AND sequence state from the audit log (D12.4).

Two responsibilities:
  - `replay` yields every recorded event (criterion #8: the log fully reconstructs a run).
  - `reconstruct_sequence_state` rebuilds the automaton's node + bindings per subject over a
    lookback window (D12.4). This is what lets a new session inherit a principal's recent chain
    progress with no second datastore — and what defends against session-rotation evasion.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from src.audit.events import AuditEvent
from src.monitor.types import SequenceState


def replay(path: Path) -> Iterator[AuditEvent]:
    """Yield every event in the log, in append order. Reconstructs every decision of a run."""
    raise NotImplementedError


def reconstruct_sequence_state(path: Path, now: float, lookback_s: float) -> SequenceState:
    """Rebuild sequence state from ChainProgress/eviction/lifecycle events within
    `[now - lookback_s, now]`. Returns an immutable SequenceState the session registry can seed
    a cold session from (D12.4, docs/design/sequence-engine.md §3)."""
    raise NotImplementedError
