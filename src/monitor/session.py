"""Session identity and sequence-state retention (D12).

The monitor assigns session identity — the agent cannot supply, choose, or rotate it (D12.2).
Nothing the agent does resets state (D12.3); state clears only on monitor-side session end or
idle expiry (default 30 min, configurable, LOGGED when it fires — D12.3).

Cross-session progress is reconstructed by REPLAYING THE AUDIT LOG over a lookback window
(default 24 h). There is no second datastore (D12.4). Per-subject chain caps evict
least-advanced-first, and EVERY eviction is its own audit event (D12.5) — never silent.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Callable, Mapping

from src.audit.events import SessionLifecycleEvent
from src.audit.replay import reconstruct_sequence_state
from src.audit.writer import AuditWriter
from src.monitor.types import Principal, SequenceState, SessionId, SubjectKey


@dataclass(frozen=True)
class RetentionConfig:
    """Operational knobs (NOT policy — kept separate, docs/design/architecture.md §3.10)."""

    idle_expiry_s: float = 30 * 60  # 30 minutes
    lookback_s: float = 24 * 60 * 60  # 24 hours
    max_chains_per_subject: int = 64  # eviction threshold


class SessionRegistry:
    """Owns live, mutable sequence state and the session lifecycle. Process-owned.

    Minimal live-state registry (issue #11): holds one in-memory `SequenceState` for the
    process, keyed internally by `SubjectKey = (session_id, principal)`. Audit-replay seeding,
    per-subject eviction, and idle expiry are the durability layer wired in issue #12 (D12.4/5).
    """

    def __init__(
        self,
        audit: AuditWriter,
        config: RetentionConfig,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._audit = audit
        self._config = config
        self._clock = clock
        self._state = SequenceState()
        self._seeded: set[SubjectKey] = set()

    def open_session(self) -> SessionId:
        """Mint a fresh monitor-assigned session id (D12.2). Agent cannot influence the value."""
        session_id = SessionId(f"s-{uuid.uuid4().hex}")
        self._audit.append(
            SessionLifecycleEvent(
                session_id=session_id, principal=None, action="open", timestamp=self._clock()
            )
        )
        return session_id

    def live_state(self) -> SequenceState:
        """The current live sequence-state snapshot, read-only. Used by the operator console's
        sequence inspector to show which chains are part-way advanced (#14)."""
        return self._state

    def state_for(
        self,
        session_id: SessionId,
        principal: str,
        node_ranks: Mapping[str, Mapping[str, int]] | None = None,
    ) -> SequenceState:
        """Return current sequence state, seeding a cold subject from history first (D15).

        The first time a (session, principal) subject is seen with no live progress, the
        principal's within-lookback chain progress is replayed from the audit log and re-keyed
        to this session — so rotating to a new session inherits the prefix instead of erasing
        it. Seeding happens once per subject; a corrupt log raises (the service then denies)
        and is retried on the next call rather than being remembered as "seeded".
        `node_ranks` (from `sequence.node_ranks`) is required to seed; without it, no seeding."""
        key = SubjectKey(session_id=session_id, principal=Principal(principal))
        if node_ranks is None or key in self._seeded:
            return self._state
        if key not in self._state.progress:
            history = reconstruct_sequence_state(
                self._audit.path,
                Principal(principal),
                session_id,
                now=self._clock(),
                lookback_s=self._config.lookback_s,
                node_ranks=node_ranks,
            )
            inherited = history.for_subject(key)
            if inherited:
                self._state = SequenceState(progress={**self._state.progress, key: inherited})
        self._seeded.add(key)
        return self._state

    def commit(self, session_id: SessionId, next_state: SequenceState) -> None:
        """Store the post-`advance` state. (#12 adds per-subject caps and least-advanced-first
        eviction with an EvictionEvent per eviction, D12.5.)"""
        self._state = next_state

    def expire_idle(self, now: float) -> tuple[SubjectKey, ...]:
        """Clear subjects idle beyond `idle_expiry_s`, writing a lifecycle event for each
        (D12.3). Deferred to #12; currently a no-op returning no cleared subjects."""
        return ()

    def end_session(self, session_id: SessionId) -> None:
        """Monitor-side session end — the only agent-independent way state clears. Logged.

        Drops the session's live subjects but does not erase within-lookback principal history
        (D15): replay reconstruction is #12's concern.
        """
        progress = {
            key: chains
            for key, chains in self._state.progress.items()
            if key.session_id != session_id
        }
        self._state = SequenceState(progress=progress)
        self._audit.append(
            SessionLifecycleEvent(
                session_id=session_id, principal=None, action="end", timestamp=self._clock()
            )
        )
