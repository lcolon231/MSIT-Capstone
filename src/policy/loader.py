"""Fail-closed YAML policy loader (D2, spec.md T2.3).

Contract:
  - Rejects unknown fields and malformed policy with clear, actionable errors.
  - Validates that every `Check.predicate` names a registered predicate (predicates.REGISTRY).
  - On ANY load/validation failure the caller must fall back to `Policy.deny_all()` — a load
    failure yields an all-DENY policy, never an empty allow (docs/design/architecture.md §3.10).
"""

from __future__ import annotations

from pathlib import Path

from src.policy.schema import Policy


class PolicyError(ValueError):
    """Raised on malformed policy, unknown fields, or an unregistered predicate reference."""


def load_policy(path: Path) -> Policy:
    """Parse and validate a YAML policy file into a `Policy`.

    Raises `PolicyError` on any problem. Callers that must not crash open should catch it and
    substitute `Policy.deny_all()` (the composition root does this).
    """
    raise NotImplementedError


def validate_policy(raw: object) -> Policy:
    """Validate an already-parsed YAML document (dict) into a typed `Policy`. Rejects unknown
    fields; checks predicate references; enforces the field freeze. Pure over `raw`."""
    raise NotImplementedError
