"""Offline DENY/GATE spike analyzer over the audit log (issue #58, optional stretch).

A spike of DENY / GATE verdicts from a single session is the classic prompt-injection tell:
an injected or misconfigured agent probing the tool boundary trips the fail-closed policy
repeatedly. The runtime SIEM alert that watches for this live is documented as a maintenance /
future-work item (report §S4); this module is its *offline* counterpart — it reads the
append-only audit log after a run and flags any session whose DENY or GATE burst meets a
configurable threshold.

By design this is a DETECTION AID only. It reads the log; it never feeds a `Decision`
(spec.md §10 — the verdict is independent of anything derived after the fact). It reuses
`src.audit.replay` as the single reader of the log, so it inherits fail-closed parsing: a
corrupt line raises `AuditFormatError` rather than being silently skipped.

    python -m src.audit.spike results/final.jsonl --deny-threshold 5 --gate-threshold 5

Exit status is non-zero when any session is flagged, so the command doubles as a simple
alert check in a scheduled job or CI step.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from src.audit.events import AuditEvent, DecisionEvent
from src.audit.replay import replay
from src.monitor.types import Principal, SessionId
from src.transport.contract import Verdict

DEFAULT_DENY_THRESHOLD = 5
DEFAULT_GATE_THRESHOLD = 5


@dataclass(frozen=True)
class SessionCounts:
    """Per-session DENY / GATE tally plus the time span it covers.

    `first_ts` / `last_ts` are the monitor-side timestamps of the first and last decision in
    the session, so a reviewer can see how tight the burst was (a spike over seconds is a far
    stronger injection signal than the same count spread over hours)."""

    session_id: SessionId
    principal: Principal | None
    deny: int
    gate: int
    total: int
    first_ts: float
    last_ts: float

    def flagged(self, deny_threshold: int, gate_threshold: int) -> bool:
        """True when this session's DENY or GATE count meets its threshold (deny-by-default
        spirit: either burst alone is enough to raise the session for review)."""
        return self.deny >= deny_threshold or self.gate >= gate_threshold

    @property
    def severity(self) -> int:
        """Ordering key: DENY (a blocked action) outweighs GATE (a paused one)."""
        return self.deny * 2 + self.gate


@dataclass
class _Accumulator:
    """Mutable per-session running tally, folded into a frozen `SessionCounts` at the end."""

    principal: Principal | None
    first_ts: float
    last_ts: float
    deny: int = 0
    gate: int = 0
    total: int = 0

    def add(self, event: DecisionEvent) -> None:
        self.total += 1
        if event.verdict is Verdict.DENY:
            self.deny += 1
        elif event.verdict is Verdict.GATE:
            self.gate += 1
        self.first_ts = min(self.first_ts, event.timestamp)
        self.last_ts = max(self.last_ts, event.timestamp)


def tally(events: Iterable[AuditEvent]) -> dict[SessionId, SessionCounts]:
    """Count DENY / GATE decisions per session over `events`. Pure; ignores non-decision
    records. The principal is taken from the session's first decision (a session acts against
    one principal — monitor/types.py `SubjectKey`)."""
    acc: dict[SessionId, _Accumulator] = {}
    for event in events:
        if not isinstance(event, DecisionEvent):
            continue
        row = acc.get(event.session_id)
        if row is None:
            row = _Accumulator(event.principal, event.timestamp, event.timestamp)
            acc[event.session_id] = row
        row.add(event)

    return {
        sid: SessionCounts(
            session_id=sid,
            principal=row.principal,
            deny=row.deny,
            gate=row.gate,
            total=row.total,
            first_ts=row.first_ts,
            last_ts=row.last_ts,
        )
        for sid, row in acc.items()
    }


def flag_spikes(
    path: Path,
    deny_threshold: int = DEFAULT_DENY_THRESHOLD,
    gate_threshold: int = DEFAULT_GATE_THRESHOLD,
) -> list[SessionCounts]:
    """Read the audit log at `path` via `replay` and return the flagged sessions, most severe
    first. Fail-closed: a corrupt log line propagates `AuditFormatError` from `replay`."""
    counts = tally(replay(path))
    flagged = [c for c in counts.values() if c.flagged(deny_threshold, gate_threshold)]
    flagged.sort(key=lambda c: (c.severity, c.session_id), reverse=True)
    return flagged


def _format(flagged: Sequence[SessionCounts], deny_threshold: int, gate_threshold: int) -> str:
    header = (
        f"DENY/GATE spike analysis  (deny>={deny_threshold}, gate>={gate_threshold})\n"
        + "=" * 56
    )
    if not flagged:
        return header + "\nno sessions exceeded the thresholds.\n"
    lines = [header, f"{len(flagged)} session(s) flagged:", ""]
    for c in flagged:
        span = c.last_ts - c.first_ts
        lines.append(
            f"  {c.session_id:<40} principal={c.principal} "
            f"deny={c.deny} gate={c.gate} total={c.total} span={span:.1f}s"
        )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.audit.spike",
        description="Flag audit-log sessions with a DENY/GATE spike (offline injection tell).",
    )
    parser.add_argument("log", help="path to the append-only audit JSONL log")
    parser.add_argument("--deny-threshold", type=int, default=DEFAULT_DENY_THRESHOLD)
    parser.add_argument("--gate-threshold", type=int, default=DEFAULT_GATE_THRESHOLD)
    args = parser.parse_args(argv)

    flagged = flag_spikes(Path(args.log), args.deny_threshold, args.gate_threshold)
    print(_format(flagged, args.deny_threshold, args.gate_threshold), end="")
    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
