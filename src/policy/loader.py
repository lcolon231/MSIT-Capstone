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
    checks = tuple(_parse_check(item, index, j) for j, item in enumerate(raw.get("checks") or ()))
    return Rule(
        rule_id=str(raw["rule_id"]),
        tool=str(raw["tool"]),
        trigger=trigger,
        checks=checks,
        enforce=enforce,
    )


def _parse_check(raw: object, rule_index: int, check_index: int) -> Check:
    where = f"rule[{rule_index}].checks[{check_index}]"
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
    if raw is None:
        return SequenceConfig()
    # Chain (kill-chain) policy parsing lands with the sequence engine in Phase 3 (#10-#12);
    # until then a `sequence:` block is rejected rather than silently dropped (fail-closed).
    raise PolicyError("sequence/chain policies are not supported yet (Phase 3)")


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
