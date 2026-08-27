"""Banking mock domain tools — issue #11 / T3.2.

The four tools operate over one in-process `BankingState`, keyed by the monitor-resolved
principal. No real money, no egress. Identity comes from the passed `principal`, never args.
"""

from __future__ import annotations

from src.tools.banking import (
    AddPayee,
    BankingState,
    GetBalance,
    ListPayees,
    TransferFunds,
    banking_tools,
    register_banking,
)
from src.tools.base import ToolRegistry


def test_get_balance_reads_principal_ledger() -> None:
    state = BankingState(balances={"acct-1": 1000})
    assert GetBalance(state).execute({}, "acct-1") == {"principal": "acct-1", "balance": 1000}


def test_get_balance_unknown_principal_is_zero_not_error() -> None:
    assert GetBalance(BankingState()).execute({}, "nobody") == {"principal": "nobody", "balance": 0}


def test_list_payees_returns_a_copy() -> None:
    state = BankingState(payees={"acct-1": ["p1", "p2"]})
    result = ListPayees(state).execute({}, "acct-1")
    assert result == {"payees": ["p1", "p2"]}
    result["payees"].append("mutated")
    assert state.payees["acct-1"] == ["p1", "p2"]  # internal ledger untouched


def test_add_payee_appends_new_and_is_idempotent() -> None:
    state = BankingState()
    AddPayee(state).execute({"payee_id": "acme"}, "acct-1")
    AddPayee(state).execute({"payee_id": "acme"}, "acct-1")  # duplicate -> no double add
    assert state.payees["acct-1"] == ["acme"]


def test_transfer_funds_debits_the_principal() -> None:
    state = BankingState(balances={"acct-1": 500})
    result = TransferFunds(state).execute({"to": "acme", "amount": 200}, "acct-1")
    assert result == {"transferred": 200, "to": "acme", "balance": 300}
    assert state.balances["acct-1"] == 300


def test_tools_share_one_ledger_across_the_domain() -> None:
    state = BankingState(balances={"acct-1": 100})
    get_balance, list_payees, add_payee, _transfer = banking_tools(state)
    add_payee.execute({"payee_id": "acme"}, "acct-1")
    assert list_payees.execute({}, "acct-1") == {"payees": ["acme"]}
    assert get_balance.execute({}, "acct-1")["balance"] == 100


def test_register_banking_populates_the_registry() -> None:
    registry = ToolRegistry()
    register_banking(registry, BankingState())
    for name in ("get_balance", "list_payees", "add_payee", "transfer_funds"):
        assert registry.get(name) is not None
    assert registry.get("no_such_tool") is None
