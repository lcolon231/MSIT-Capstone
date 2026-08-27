"""Banking mock domain — the canonical kill-chain surface (spec.md T3.2).

Four tools over an in-process `BankingState`: get_balance, list_payees, add_payee,
transfer_funds. Each passes per-call checks individually; only their composition is the fraud
the sequence engine blocks (docs/design/sequence-engine.md §4). `transfer_funds` is a D5
fund-transfer gate class.

No real money, no egress — the ledger is a plain in-process dict keyed by the monitor-resolved
principal. Tools never read identity from agent-supplied args; the service passes `principal`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from src.tools.base import ToolRegistry


@dataclass
class BankingState:
    """In-process ledger for the mock domain. No real money, no egress."""

    balances: dict[str, int] = field(default_factory=dict)  # principal -> minor units
    payees: dict[str, list[str]] = field(default_factory=dict)  # principal -> payee ids


class GetBalance:
    name = "get_balance"

    def __init__(self, state: BankingState) -> None:
        self._state = state

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        return {"principal": principal, "balance": self._state.balances.get(principal, 0)}


class ListPayees:
    name = "list_payees"

    def __init__(self, state: BankingState) -> None:
        self._state = state

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        return {"payees": list(self._state.payees.get(principal, []))}


class AddPayee:
    name = "add_payee"

    def __init__(self, state: BankingState) -> None:
        self._state = state

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        payee_id = args.get("payee_id")
        payees = self._state.payees.setdefault(principal, [])
        if payee_id is not None and payee_id not in payees:
            payees.append(str(payee_id))
        return {"payees": list(payees)}


class TransferFunds:
    name = "transfer_funds"  # D5 fund-transfer gate class

    def __init__(self, state: BankingState) -> None:
        self._state = state

    def execute(self, args: Mapping[str, Any], principal: str) -> Any:
        to = args.get("to")
        amount = int(args.get("amount", 0))
        balance = self._state.balances.get(principal, 0) - amount
        self._state.balances[principal] = balance
        return {"transferred": amount, "to": to, "balance": balance}


def banking_tools(state: BankingState) -> tuple[GetBalance, ListPayees, AddPayee, TransferFunds]:
    """Construct the four banking tools sharing one in-process ledger."""
    return GetBalance(state), ListPayees(state), AddPayee(state), TransferFunds(state)


def register_banking(registry: ToolRegistry, state: BankingState) -> None:
    """Register the banking domain into a monitor `ToolRegistry`."""
    for tool in banking_tools(state):
        registry.register(tool)
