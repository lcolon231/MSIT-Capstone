"""Named predicate registry — the vetted, pure functions policy YAML may reference by name.

This is how the monitor stays argument-aware while keeping policy as *data* (D2): the YAML
names a predicate; the code that decides is here, version-controlled and red-teamable, never
authored by the agent or inlined in policy. The loader validates that every `Check.predicate`
resolves in `REGISTRY` (fail-closed at load time).

Matchers must be anchored / canonicalizing to resist the parameter-abuse classes in
qa-redteam-plan.md T3.2 (encoding evasion, path traversal, look-alike domains).
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from src.monitor.types import ToolCall

# A predicate takes the enriched call plus its YAML params and returns a plain bool. Pure.
Predicate = Callable[[ToolCall, Mapping[str, Any]], bool]

REGISTRY: dict[str, Predicate] = {}


def register(name: str) -> Callable[[Predicate], Predicate]:
    """Decorator to add a predicate to REGISTRY under `name`.

    Minimal real infrastructure (not verdict logic): it must run at import so the registry is
    populated and the loader can validate `Check.predicate` references. The predicate *bodies*
    remain NotImplementedError until Phase 2.
    """

    def _decorator(fn: Predicate) -> Predicate:
        REGISTRY[name] = fn
        return fn

    return _decorator


def resolve(name: str) -> Predicate:
    """Return the predicate registered under `name`, or raise KeyError (the loader turns this
    into a clear, fail-closed load error)."""
    return REGISTRY[name]


# --- Predicate signatures (bodies deferred to Phase 2) -----------------------------------

@register("arg_equals")
def arg_equals(call: ToolCall, params: Mapping[str, Any]) -> bool:
    """True iff the named argument equals an expected value."""
    raise NotImplementedError


@register("arg_matches")
def arg_matches(call: ToolCall, params: Mapping[str, Any]) -> bool:
    """True iff the named argument matches an ANCHORED regex (^...$). Anchoring is mandatory —
    an unanchored pattern is the look-alike-domain / traversal hole (qa-redteam-plan.md T3.2)."""
    raise NotImplementedError


@register("is_destructive_cmd")
def is_destructive_cmd(call: ToolCall, params: Mapping[str, Any]) -> bool:
    """True for a destructive shell command after canonicalization (decode ${IFS}, base64,
    unicode homoglyphs) — e.g. `rm -rf /`. `shell("ls")` is False."""
    raise NotImplementedError


@register("target_is_bound_payee")
def target_is_bound_payee(call: ToolCall, params: Mapping[str, Any]) -> bool:
    """Sequence predicate: True iff `transfer_funds` targets the payee bound at add_payee
    (the terminal kill-chain transition, docs/design/sequence-engine.md §5)."""
    raise NotImplementedError
