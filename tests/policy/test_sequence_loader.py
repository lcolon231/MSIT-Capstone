"""Sequence/chain YAML parsing — issue #12 / T3.3.

The loader turns the `sequence:` block (design-doc key style: `from`/`to`/`checks`) into typed
`ChainSpec`/`ChainStep` values, fail-closed on unknown fields, missing required keys, or an
unregistered check predicate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.policy.loader import PolicyError, load_policy, validate_policy
from src.transport.contract import Verdict

REPO_ROOT = Path(__file__).resolve().parents[2]
RMM = REPO_ROOT / "policies" / "rmm.yaml"


def _seq(*steps: dict) -> dict:
    return {"rules": [], "sequence": {"chains": [{"name": "c", "domain": "rmm", "steps": list(steps)}]}}


# --- the real rmm.yaml ----------------------------------------------------------------


def test_rmm_yaml_loads_the_canonical_chain() -> None:
    policy = load_policy(RMM)
    (chain,) = policy.sequence.chains
    assert chain.name == "recon_register_exfil"
    assert chain.domain == "rmm"
    assert tuple(s.trigger for s in chain.steps) == (
        "list_endpoints",
        "list_shares",
        "register_destination",
        "export_records",
    )


def test_from_and_to_map_to_node_fields() -> None:
    chain = load_policy(RMM).sequence.chains[0]
    list_endpoints, list_shares, register_destination, transfer = chain.steps
    assert list_endpoints.from_node is None and list_endpoints.to_node == "S1_ENDPOINTS"
    assert list_shares.from_node == "S1_ENDPOINTS" and list_shares.to_node == "S2_SHARES"
    assert register_destination.to_node == "S3_DESTINATION_ADDED"
    assert transfer.from_node == "S3_DESTINATION_ADDED" and transfer.to_node == "S4_BLOCKED"


def test_terminal_step_is_deny_with_binding_check() -> None:
    transfer = load_policy(RMM).sequence.chains[0].steps[3]
    assert transfer.enforce is Verdict.DENY
    assert transfer.rule_id == "seq.recon_register_exfil.terminal"
    (check,) = transfer.checks
    assert check.predicate == "target_is_bound_value"
    assert check.params == {"argument": "to", "binding": "registered_destination"}


def test_register_destination_step_binds_the_destination() -> None:
    register_destination = load_policy(RMM).sequence.chains[0].steps[2]
    assert register_destination.bind == {"registered_destination": "args.destination"}
    assert register_destination.enforce is None  # forward step, not blocking


# --- fail-closed parsing ------------------------------------------------------------------


def test_step_missing_to_is_rejected() -> None:
    with pytest.raises(PolicyError):
        validate_policy(_seq({"trigger": "list_endpoints"}))


def test_step_missing_trigger_is_rejected() -> None:
    with pytest.raises(PolicyError):
        validate_policy(_seq({"to": "S1"}))


def test_unknown_step_field_is_rejected() -> None:
    with pytest.raises(PolicyError):
        validate_policy(_seq({"trigger": "list_endpoints", "to": "S1", "bogus": 1}))


def test_unregistered_check_predicate_is_rejected() -> None:
    with pytest.raises(PolicyError):
        validate_policy(
            _seq({"trigger": "export_records", "to": "S4", "checks": [{"predicate": "no_such_pred"}]})
        )


def test_chain_with_no_steps_is_rejected() -> None:
    with pytest.raises(PolicyError):
        validate_policy({"rules": [], "sequence": {"chains": [{"name": "c", "domain": "rmm", "steps": []}]}})


def test_unknown_sequence_field_is_rejected() -> None:
    with pytest.raises(PolicyError):
        validate_policy({"rules": [], "sequence": {"chains": [], "bogus": 1}})


def test_invalid_enforce_value_is_rejected() -> None:
    with pytest.raises(PolicyError):
        validate_policy(_seq({"trigger": "export_records", "to": "S4", "enforce": "nuke"}))
