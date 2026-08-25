"""Kill-chain automaton (D1) — the hero mechanism.

Two pure functions (docs/design/sequence-engine.md §6):
  - `classify` runs inside `evaluate` (read-only): does this call reach a blocking/escalating
    transition of a modeled chain for this subject? Returns DENY/GATE or None.
  - `advance` runs in the service layer AFTER a permitted call executes: returns the next
    SequenceState. Never called for a DENY'd call, so the terminal transfer never advances.

Deterministic finite automaton per (subject, modeled chain). No probabilities, no windows.
Recognizes only pre-modeled chains (bounded — Schneider 2000; see residual-risks.md R2).
"""

from __future__ import annotations

from src.monitor.types import Decision, SequenceState, SubjectKey, ToolCall
from src.policy.schema import Policy


def classify(call: ToolCall, state: SequenceState, policy: Policy) -> Decision | None:
    """Return a Decision (DENY or GATE) iff `call` reaches a blocking/escalating transition of
    some modeled chain for `call`'s subject; otherwise None (let per-call policy decide).

    DENY  = full kill chain (recon prefix + add new payee + transfer to THAT payee).
    GATE  = near-miss escalation (recon+add present, transfer target/amount ambiguous).
    Pure; no I/O, no mutation (docs/design/sequence-engine.md §8).
    """
    raise NotImplementedError


def advance(call: ToolCall, state: SequenceState) -> SequenceState:
    """Return the next SequenceState after a PERMITTED, executed `call` moves modeled chains
    forward. Idempotent on duplicate steps; benign/unmatched calls neither advance nor reset
    (docs/design/sequence-engine.md §7). Pure — returns a new state, mutates nothing."""
    raise NotImplementedError


def subject_of(call: ToolCall) -> SubjectKey:
    """The (session_id, principal) subject key a call is tracked under (D12.1). Pure."""
    raise NotImplementedError
