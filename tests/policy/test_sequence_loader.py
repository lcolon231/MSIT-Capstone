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
BANKING = REPO_ROOT / "policies" / "banking.yaml"


def _seq(*steps: dict) -> dict:
    return {"rules": [], "sequence": {"chains": [{"name": "c", "domain": "banking", "steps": list(steps)}]}}


# --- the real banking.yaml ----------------------------------------------------------------


def test_banking_yaml_loads_the_canonical_chain() -> None:
    policy = load_policy(BANKING)
    (chain,) = policy.sequence.chains
    assert chain.name == "recon_add_drain"
    assert chain.domain == "banking"
    assert tuple(s.trigger for s in chain.steps) == (
        "get_balance",
        "list_payees",
        "add_payee",
        "transfer_funds",
    )


def test_from_and_to_map_to_node_fields() -> None:
    chain = load_policy(BANKING).sequence.chains[0]
    get_balance, list_payees, add_payee, transfer = chain.steps
    assert get_balance.from_node is None and get_balance.to_node == "S1_BALANCE"
    assert list_payees.from_node == "S1_BALANCE" and list_payees.to_node == "S2_PAYEES"
    assert add_payee.to_node == "S3_PAYEE_ADDED"
    assert transfer.from_node == "S3_PAYEE_ADDED" and transfer.to_node == "S4_BLOCKED"


def test_terminal_step_is_deny_with_binding_check() -> None:
    transfer = load_policy(BANKING).sequence.chains[0].steps[3]
    assert transfer.enforce is Verdict.DENY
    assert transfer.rule_id == "seq.recon_add_drain.terminal"
    (check,) = transfer.checks
    assert check.predicate == "target_is_bound_payee"
    assert check.params == {"argument": "to", "binding": "added_payee_id"}


def test_add_payee_step_binds_the_payee() -> None:
    add_payee = load_policy(BANKING).sequence.chains[0].steps[2]
    assert add_payee.bind == {"added_payee_id": "args.payee_id"}
    assert add_payee.enforce is None  # forward step, not blocking


# --- fail-closed parsing ------------------------------------------------------------------


def test_step_missing_to_is_rejected() -> None:
    with pytest.raises(PolicyError):
        validate_policy(_seq({"trigger": "get_balance"}))


def test_step_missing_trigger_is_rejected() -> None:
    with pytest.raises(PolicyError):
        validate_policy(_seq({"to": "S1"}))


def test_unknown_step_field_is_rejected() -> None:
    with pytest.raises(PolicyError):
        validate_policy(_seq({"trigger": "get_balance", "to": "S1", "bogus": 1}))


def test_unregistered_check_predicate_is_rejected() -> None:
    with pytest.raises(PolicyError):
        validate_policy(
            _seq({"trigger": "transfer_funds", "to": "S4", "checks": [{"predicate": "no_such_pred"}]})
        )


def test_chain_with_no_steps_is_rejected() -> None:
    with pytest.raises(PolicyError):
        validate_policy({"rules": [], "sequence": {"chains": [{"name": "c", "domain": "banking", "steps": []}]}})


def test_unknown_sequence_field_is_rejected() -> None:
    with pytest.raises(PolicyError):
        validate_policy({"rules": [], "sequence": {"chains": [], "bogus": 1}})


def test_invalid_enforce_value_is_rejected() -> None:
    with pytest.raises(PolicyError):
        validate_policy(_seq({"trigger": "transfer_funds", "to": "S4", "enforce": "nuke"}))
