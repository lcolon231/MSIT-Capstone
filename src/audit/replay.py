"""Replay — reconstruct decisions AND sequence state from the audit log (D12.4).

Two responsibilities:
  - `replay` yields every recorded event (criterion #8: the log fully reconstructs a run).
  - `reconstruct_sequence_state` rebuilds the automaton's node + bindings per subject over a
    lookback window (D12.4). This is what lets a new session inherit a principal's recent chain
    progress with no second datastore — and what defends against session-rotation evasion.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, Mapping

from src.audit.events import AuditEvent, ChainProgressEvent, EvictionEvent, from_jsonl
from src.monitor.types import ChainProgress, Principal, SequenceState, SessionId, SubjectKey


def replay(path: Path) -> Iterator[AuditEvent]:
    """Yield every event in the log, in append order. Reconstructs every decision of a run.

    A corrupt line raises `AuditFormatError` rather than being silently skipped (fail-closed;
    interface-contracts.md §4.7).
    """
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                yield from_jsonl(stripped)


def reconstruct_sequence_state(
    path: Path,
    principal: Principal,
    new_session: SessionId,
    now: float,
    lookback_s: float,
    node_ranks: Mapping[str, Mapping[str, int]],
) -> SequenceState:
    """Rebuild `principal`'s chain progress from the log and key it to `new_session` (D15).

    Folds every ChainProgressEvent for the principal — from ANY session — whose timestamp lies in
    `[now - lookback_s, now]`, in append order:
      * an event moves a chain only to a node at least as deep as the one already held
        (`node_ranks`), so a later, shallower event never undoes progress; at equal depth the
        newer binding digests win (a re-bind);
      * an event for an unknown chain/node (policy has since changed) is ignored;
      * an EvictionEvent at the chain's current node drops that chain (D12.5).
    Session end / idle-expiry events are NOT replay barriers (D15). A missing log means no
    history; a corrupt record raises `AuditFormatError` — never silently skipped.
    """
    if not Path(path).exists():
        return SequenceState()
    earliest = now - lookback_s
    chains: dict[str, ChainProgress] = {}
    for event in replay(path):
        if not isinstance(event, (ChainProgressEvent, EvictionEvent)):
            continue
        if event.principal != principal or not earliest <= event.timestamp <= now:
            continue
        if isinstance(event, EvictionEvent):
            current = chains.get(event.chain)
            if current is not None and current.node == event.evicted_node:
                del chains[event.chain]
            continue
        ranks = node_ranks.get(event.chain, {})
        depth = ranks.get(event.to_node)
        if depth is None:
            continue
        current = chains.get(event.chain)
        if current is not None and depth < ranks.get(current.node, 0):
            continue
        step_times = dict(current.step_times) if current is not None else {}
        step_times[event.to_node] = event.timestamp
        chains[event.chain] = ChainProgress(
            chain=event.chain,
            node=event.to_node,
            bindings=dict(event.bindings),
            step_times=step_times,
            updated_at=event.timestamp,
        )
    if not chains:
        return SequenceState()
    key = SubjectKey(session_id=new_session, principal=principal)
    return SequenceState(progress={key: tuple(chains.values())})
