"""Fail-closed YAML policy loader (D2, spec.md T2.3).

Contract:
  - Rejects unknown fields and malformed policy with clear, actionable errors.
  - Validates that every `Check.predicate` names a registered predicate (predicates.REGISTRY).
  - On ANY load/validation failure the caller must fall back to `Policy.deny_all()` — a load
    failure yields an all-DENY policy, never an empty allow (docs/design/architecture.md §3.10).
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import TypeVar

import yaml

from src.policy import predicates
from src.policy.schema import (
    ChainSpec,
    ChainStep,
    Check,
    Policy,
    Rule,
    SequenceConfig,
    TriggerEvent,
)
from src.transport.contract import Verdict

_E = TypeVar("_E", bound=Enum)

_TOP_FIELDS = frozenset({"rules", "sequence"})
_RULE_FIELDS = frozenset({"rule_id", "tool", "trigger", "checks", "enforce"})
_RULE_REQUIRED = ("rule_id", "tool", "trigger", "enforce")
_CHECK_FIELDS = frozenset({"predicate", "params", "negate"})
_SEQUENCE_FIELDS = frozenset({"chains"})
_CHAIN_FIELDS = frozenset({"name", "domain", "steps"})
_CHAIN_REQUIRED = ("name", "domain", "steps")
# Design-doc key style (sequence-engine.md §9): short `from`/`to` node keys mapped to the
# ChainStep dataclass's from_node/to_node.
_STEP_FIELDS = frozenset({"trigger", "from", "to", "checks", "bind", "enforce", "rule_id"})
_STEP_REQUIRED = ("trigger", "to")


class PolicyError(ValueError):
    """Raised on malformed policy, unknown fields, or an unregistered predicate reference."""


def load_policy(path: Path) -> Policy:
    """Parse and validate a YAML policy file into a `Policy`.

    Raises `PolicyError` on any problem. Callers that must not crash open should catch it and
    substitute `Policy.deny_all()` (the composition root does this).
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"malformed YAML in {path}: {exc}") from exc
    return validate_policy(raw)


def validate_policy(raw: object) -> Policy:
    """Validate an already-parsed YAML document (dict) into a typed `Policy`. Rejects unknown
    fields; checks predicate references; enforces the field freeze. Pure over `raw`."""
    if not isinstance(raw, dict):
        raise PolicyError(f"policy must be a mapping, got {type(raw).__name__}")
    _reject_unknown(raw, _TOP_FIELDS, "policy")
    rules = tuple(_parse_rule(item, i) for i, item in enumerate(raw.get("rules") or ()))
    sequence = _parse_sequence(raw.get("sequence"))
    return Policy(rules=rules, sequence=sequence)


def _parse_rule(raw: object, index: int) -> Rule:
    where = f"rule[{index}]"
    if not isinstance(raw, dict):
        raise PolicyError(f"{where} must be a mapping, got {type(raw).__name__}")
    _reject_unknown(raw, _RULE_FIELDS, where)
    for field_name in _RULE_REQUIRED:
        if field_name not in raw:
            raise PolicyError(f"{where} missing required field '{field_name}'")
    trigger = _parse_enum(TriggerEvent, raw["trigger"], f"{where}.trigger")
    enforce = _parse_enum(Verdict, raw["enforce"], f"{where}.enforce")
    checks = tuple(
        _parse_check(item, f"{where}.checks[{j}]") for j, item in enumerate(raw.get("checks") or ())
    )
    return Rule(
        rule_id=str(raw["rule_id"]),
        tool=str(raw["tool"]),
        trigger=trigger,
        checks=checks,
        enforce=enforce,
    )


def _parse_check(raw: object, where: str) -> Check:
    if not isinstance(raw, dict):
        raise PolicyError(f"{where} must be a mapping, got {type(raw).__name__}")
    _reject_unknown(raw, _CHECK_FIELDS, where)
    if "predicate" not in raw:
        raise PolicyError(f"{where} missing required field 'predicate'")
    predicate = str(raw["predicate"])
    if predicate not in predicates.REGISTRY:
        raise PolicyError(f"{where} references unregistered predicate '{predicate}'")
    params = raw.get("params") or {}
    if not isinstance(params, dict):
        raise PolicyError(f"{where}.params must be a mapping, got {type(params).__name__}")
    return Check(predicate=predicate, params=params, negate=bool(raw.get("negate", False)))


def _parse_sequence(raw: object) -> SequenceConfig:
    """Parse the `sequence:` block into modeled kill chains (D1). Fail-closed: unknown fields,
    missing required step keys, or an unregistered check predicate all raise `PolicyError`."""
    if raw is None:
        return SequenceConfig()
    if not isinstance(raw, dict):
        raise PolicyError(f"sequence must be a mapping, got {type(raw).__name__}")
    _reject_unknown(raw, _SEQUENCE_FIELDS, "sequence")
    chains = tuple(_parse_chain(item, i) for i, item in enumerate(raw.get("chains") or ()))
    return SequenceConfig(chains=chains)


def _parse_chain(raw: object, index: int) -> ChainSpec:
    where = f"sequence.chains[{index}]"
    if not isinstance(raw, dict):
        raise PolicyError(f"{where} must be a mapping, got {type(raw).__name__}")
    _reject_unknown(raw, _CHAIN_FIELDS, where)
    for field_name in _CHAIN_REQUIRED:
        if field_name not in raw:
            raise PolicyError(f"{where} missing required field '{field_name}'")
    steps = tuple(
        _parse_step(item, where, j) for j, item in enumerate(raw.get("steps") or ())
    )
    if not steps:
        raise PolicyError(f"{where} must declare at least one step")
    return ChainSpec(name=str(raw["name"]), domain=str(raw["domain"]), steps=steps)


def _parse_step(raw: object, chain_where: str, index: int) -> ChainStep:
    where = f"{chain_where}.steps[{index}]"
    if not isinstance(raw, dict):
        raise PolicyError(f"{where} must be a mapping, got {type(raw).__name__}")
    _reject_unknown(raw, _STEP_FIELDS, where)
    for field_name in _STEP_REQUIRED:
        if field_name not in raw:
            raise PolicyError(f"{where} missing required field '{field_name}'")
    checks = tuple(
        _parse_check(item, f"{where}.checks[{k}]") for k, item in enumerate(raw.get("checks") or ())
    )
    enforce = _parse_enum(Verdict, raw["enforce"], f"{where}.enforce") if "enforce" in raw else None
    bind_raw = raw.get("bind") or {}
    if not isinstance(bind_raw, dict):
        raise PolicyError(f"{where}.bind must be a mapping, got {type(bind_raw).__name__}")
    from_raw = raw.get("from")
    return ChainStep(
        trigger=str(raw["trigger"]),
        to_node=str(raw["to"]),
        from_node=None if from_raw is None else str(from_raw),
        checks=checks,
        bind={str(k): str(v) for k, v in bind_raw.items()},
        enforce=enforce,
        rule_id=None if "rule_id" not in raw else str(raw["rule_id"]),
    )


def _parse_enum(enum_cls: type[_E], value: object, where: str) -> _E:
    try:
        return enum_cls(value)
    except ValueError:
        allowed = [member.value for member in enum_cls]
        raise PolicyError(f"{where}: invalid value {value!r}; allowed: {allowed}") from None


def _reject_unknown(raw: dict[object, object], allowed: frozenset[str], where: str) -> None:
    unknown = set(raw) - set(allowed)
    if unknown:
        raise PolicyError(f"{where}: unknown field(s) {sorted(map(str, unknown))}")
