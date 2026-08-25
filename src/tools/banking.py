"""Banking mock domain — the canonical kill-chain surface (spec.md T3.2).

Four tools over an in-process `BankingState`: get_balance, list_payees, add_payee,
transfer_funds. Each passes per-call checks individually; only their composition is the fraud
the sequence engine blocks (docs/design/sequence-engine.md §4). `transfer_funds` is a D5
fund-transfer gate class.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from src.transport.contract import ToolResult


@dataclass
class BankingState:
    """In-process ledger for the mock domain. No real money, no egress."""

    balances: dict[str, int] = field(default_factory=dict)  # principal -> minor units
    payees: dict[str, list[str]] = field(default_factory=dict)  # principal -> payee ids


class GetBalance:
    name = "get_balance"

    def execute(self, args: Mapping[str, Any]) -> ToolResult:
        raise NotImplementedError


class ListPayees:
    name = "list_payees"

    def execute(self, args: Mapping[str, Any]) -> ToolResult:
        raise NotImplementedError


class AddPayee:
    name = "add_payee"

    def execute(self, args: Mapping[str, Any]) -> ToolResult:
        raise NotImplementedError


class TransferFunds:
    name = "transfer_funds"  # D5 fund-transfer gate class

    def execute(self, args: Mapping[str, Any]) -> ToolResult:
        raise NotImplementedError
