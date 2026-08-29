"""Kill-chain automaton (D1) — the hero mechanism.

Two pure functions (docs/design/sequence-engine.md §6):
  - `classify` runs inside `evaluate` (read-only): does this call reach a blocking/escalating
    transition of a modeled chain for this subject? Returns DENY/GATE or None.
  - `advance` runs in the service layer AFTER a permitted call executes: returns the next
    SequenceState. Never called for a DENY'd call, so the terminal transfer never advances.

Deterministic finite automaton per (subject, modeled chain). No probabilities, no windows.
Recognizes only pre-modeled chains (bounded — Schneider 2000; see residual-risks.md R2).

State is keyed on the SubjectKey `(session_id, principal)` (D12.1). A chain with no retained
progress sits at the implicit start node `None` (S0_IDLE); the first step's `from_node` is also
`None`, so it is the only step reachable from a cold start.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

from src.monitor.types import (
    ChainProgress,
    Decision,
    SequenceState,
    SubjectKey,
    ToolCall,
)
from src.policy import predicates
from src.policy.schema import ChainSpec, ChainStep, Check, Policy

# The implicit start node: a chain with no retained ChainProgress sits here (S0_IDLE). The
# canonical first step declares `from_node=None`, so it is what a cold chain matches against.
START_NODE: str | None = None


def classify(call: ToolCall, state: SequenceState, policy: Policy) -> Decision | None:
    """Return a Decision (DENY or GATE) iff `call` reaches a blocking/escalating transition of
    some modeled chain for `call`'s subject; otherwise None (let per-call policy decide).

    DENY  = full kill chain (recon prefix + register a new destination + export to THAT destination).
    GATE  = a modeled escalation whose step carries `enforce: GATE`.
    Pure; no I/O, no mutation (docs/design/sequence-engine.md §8). Fail-closed: a step whose
    checks raise or whose binding is absent does not fire, so it can only ever *tighten*.
    """
    if not policy.sequence.chains:
        # No modeled chains => nothing to classify; per-call policy decides.
        return None
    key = subject_of(call)
    for chain in policy.sequence.chains:
        progress = _progress_for(state, key, chain.name)
        current_node = progress.node if progress is not None else START_NODE
        bindings = progress.bindings if progress is not None else {}
        for step in chain.steps:
            if step.enforce is None:  # only blocking/escalating steps emit a verdict
                continue
            if step.trigger != call.tool or step.from_node != current_node:
                continue
            if not _blocking_checks_pass(step.checks, call, bindings):
                continue  # near-miss: fall through so per-call policy (D5 GATE) decides
            return _decision_for(chain, step)
    return None


def advance(call: ToolCall, policy: Policy, state: SequenceState) -> SequenceState:
    """Return the next SequenceState after a PERMITTED, executed `call` moves modeled chains
    forward. Idempotent on duplicate steps; benign/unmatched calls neither advance nor reset
    (docs/design/sequence-engine.md §7). Pure — returns a new state, mutates nothing.

    Only non-blocking steps (`enforce is None`) advance here: the terminal transfer is DENY'd,
    so it never executes and never reaches its trap node via `advance` (design §6).
    """
    key = subject_of(call)
    by_chain = {p.chain: p for p in state.for_subject(key)}
    changed = False
    for chain in policy.sequence.chains:
        current = by_chain.get(chain.name)
        current_node = current.node if current is not None else START_NODE
        step = _forward_step(chain, current_node, call)
        if step is None:
            continue  # unmatched call: neither advance nor reset
        by_chain[chain.name] = _apply_step(chain.name, current, step, call)
        changed = True
    if not changed:
        return state
    progress = dict(state.progress)
    progress[key] = tuple(by_chain.values())
    return SequenceState(progress=progress)


def subject_of(call: ToolCall) -> SubjectKey:
    """The (session_id, principal) subject key a call is tracked under (D12.1). Pure."""
    return SubjectKey(session_id=call.session_id, principal=call.principal)


# --- internals ---------------------------------------------------------------------------


def _progress_for(state: SequenceState, key: SubjectKey, chain: str) -> ChainProgress | None:
    """The retained progress for one subject+chain, or None if the chain is cold."""
    for progress in state.for_subject(key):
        if progress.chain == chain:
            return progress
    return None


def _forward_step(chain: ChainSpec, current_node: str | None, call: ToolCall) -> ChainStep | None:
    """The single non-blocking step this call advances, in declared order, or None.

    A step matches when its trigger and per-call checks hold AND either:
      * `from_node == current_node`  — a normal forward transition, or
      * `to_node   == current_node`  — an idempotent replay of the step that reached this node
        (a duplicate `register_destination` in S3 re-binds to the latest digest without an off-by-one
        advance; design §7). Forward transitions are preferred over idempotent replays.
    """
    idempotent: ChainStep | None = None
    for step in chain.steps:
        if step.enforce is not None or step.trigger != call.tool:
            continue
        if not _percall_checks_pass(step.checks, call):
            continue
        if step.from_node == current_node:
            return step
        if step.to_node == current_node and idempotent is None:
            idempotent = step
    return idempotent


def _apply_step(chain: str, current: ChainProgress | None, step: ChainStep, call: ToolCall) -> ChainProgress:
    """The new ChainProgress after `step` fires: move to `to_node`, capture bindings as canonical
    digests (never plaintext — design §10), and stamp the step time."""
    bindings = dict(current.bindings) if current is not None else {}
    for name, source in step.bind.items():
        value = _resolve_source(source, call)
        if value is not None:  # only bind when the source argument is actually present
            bindings[name] = _canonical_digest(value)
    step_times = dict(current.step_times) if current is not None else {}
    step_times[step.to_node] = call.timestamp
    return ChainProgress(
        chain=chain,
        node=step.to_node,
        bindings=bindings,
        step_times=step_times,
        updated_at=call.timestamp,
    )


def _decision_for(chain: ChainSpec, step: ChainStep) -> Decision:
    """The Decision emitted when a blocking/escalating step fires."""
    verdict = step.enforce  # DENY or GATE; classify only calls this for enforce'd steps
    assert verdict is not None, "blocking step must declare enforce"
    rule_id = step.rule_id or f"seq.{chain.name}.{step.to_node}"
    return Decision(
        verdict=verdict,
        rule_id=rule_id,
        reason=f"modeled chain '{chain.name}' reached blocking transition -> {step.to_node}",
    )


def _percall_checks_pass(checks: Sequence[Check], call: ToolCall) -> bool:
    """Evaluate a forward step's checks through the vetted per-call predicate registry,
    fail-closed (mirrors schema._check_holds). Forward steps need no binding context."""
    for check in checks:
        try:
            result = predicates.resolve(check.predicate)(call, check.params)
        except Exception:
            return False
        if bool(result) == check.negate:
            return False
    return True


def _blocking_checks_pass(checks: Sequence[Check], call: ToolCall, bindings: Mapping[str, Any]) -> bool:
    """Evaluate a blocking step's checks with monitor-owned binding context (design §9). These
    are *sequence* predicates — they receive the captured binding digests, which are never YAML
    and never agent-authored. Fail-closed: unknown predicate, missing binding, or an exception
    all count as 'does not fire', so the sequence layer can only tighten."""
    for check in checks:
        if not _sequence_check(check, call, bindings):
            return False
    return True


def _sequence_check(check: Check, call: ToolCall, bindings: Mapping[str, Any]) -> bool:
    """One binding-aware sequence check. Currently supports `target_is_bound_value`: the named
    argument's canonical digest must equal a previously captured binding (design §5)."""
    try:
        if check.predicate == "target_is_bound_value":
            bound = bindings.get(check.params["binding"])
            value = call.args.get(check.params["argument"])
            if bound is None or value is None:
                result = False
            else:
                result = _canonical_digest(value) == bound
            return result != check.negate
    except Exception:
        return False
    return False  # unknown sequence predicate: fail closed


def _resolve_source(source: str, call: ToolCall) -> Any:
    """Resolve a bind source expression (e.g. ``"args.destination"``) against the enriched call.
    Only the monitor-owned ``args.<name>`` form is supported; anything else binds nothing."""
    prefix = "args."
    if source.startswith(prefix):
        return call.args.get(source[len(prefix):])
    return None


def _canonical_digest(value: Any) -> str:
    """Canonical SHA-256 over one value (design §4). Deterministic and plaintext-free, so the
    same destination compared at register-time and export-time yields identical digests."""
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
