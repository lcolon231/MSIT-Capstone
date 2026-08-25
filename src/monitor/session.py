"""Session identity and sequence-state retention (D12).

The monitor assigns session identity — the agent cannot supply, choose, or rotate it (D12.2).
Nothing the agent does resets state (D12.3); state clears only on monitor-side session end or
idle expiry (default 30 min, configurable, LOGGED when it fires — D12.3).

Cross-session progress is reconstructed by REPLAYING THE AUDIT LOG over a lookback window
(default 24 h). There is no second datastore (D12.4). Per-subject chain caps evict
least-advanced-first, and EVERY eviction is its own audit event (D12.5) — never silent.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.audit.writer import AuditWriter
from src.monitor.types import SequenceState, SessionId, SubjectKey


@dataclass(frozen=True)
class RetentionConfig:
    """Operational knobs (NOT policy — kept separate, docs/design/architecture.md §3.10)."""

    idle_expiry_s: float = 30 * 60  # 30 minutes
    lookback_s: float = 24 * 60 * 60  # 24 hours
    max_chains_per_subject: int = 64  # eviction threshold


class SessionRegistry:
    """Owns live, mutable sequence state and the session lifecycle. Process-owned."""

    def __init__(self, audit: AuditWriter, config: RetentionConfig) -> None:
        raise NotImplementedError

    def open_session(self) -> SessionId:
        """Mint a fresh monitor-assigned session id (D12.2). Agent cannot influence the value."""
        raise NotImplementedError

    def state_for(self, session_id: SessionId, principal: str) -> SequenceState:
        """Return current sequence state for a subject, seeding a new session from the
        principal's audit history via replay when the in-memory copy is cold (D12.4)."""
        raise NotImplementedError

    def commit(self, session_id: SessionId, next_state: SequenceState) -> None:
        """Store the post-`advance` state. Enforces per-subject caps, evicting
        least-advanced-first and writing an EvictionEvent per eviction (D12.5)."""
        raise NotImplementedError

    def expire_idle(self, now: float) -> tuple[SubjectKey, ...]:
        """Clear subjects idle beyond `idle_expiry_s`, writing a lifecycle event for each
        (D12.3). Returns the cleared subjects."""
        raise NotImplementedError

    def end_session(self, session_id: SessionId) -> None:
        """Monitor-side session end — the only agent-independent way state clears. Logged."""
        raise NotImplementedError
