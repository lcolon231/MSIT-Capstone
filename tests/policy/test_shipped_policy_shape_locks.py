"""Every ALLOW rule in the shipped policies is shape-locked with `args_allowlist` (issue #57).

An ALLOW rule without a shape lock admits any argument key, so a call can smuggle keys the tool
was never meant to take. These tests pin both halves: each shipped ALLOW rule carries the check,
and a call with an extra key falls through to the default DENY while the declared shape is
still allowed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.monitor.types import CallId, Principal, SequenceState, SessionId, ToolCall
from src.monitor.verdict import evaluate
from src.policy.loader import load_policy
from src.transport.contract import Verdict

POLICIES = Path(__file__).resolve().parents[2] / "policies"
SHIPPED = ("rmm.yaml", "msp.yaml")

# (policy, tool, the tool's declared argument shape)
ALLOWED_SHAPES = [
    ("rmm.yaml", "list_endpoints", {}),
    ("rmm.yaml", "list_shares", {}),
    ("rmm.yaml", "register_destination", {"destination": "approved-dest"}),
    ("msp.yaml", "list_endpoints", {}),
    ("msp.yaml", "list_shares", {}),
    ("msp.yaml", "register_destination", {"destination": "approved-dest"}),
    ("msp.yaml", "list_files", {}),
    ("msp.yaml", "read_file", {"path": "notes.txt"}),
    ("msp.yaml", "fetch_url", {"url": "https://status.example.com"}),
    ("msp.yaml", "list_credentials", {}),
]


def call(tool: str, args: dict[str, object]) -> ToolCall:
    return ToolCall(
        tool=tool,
        args=args,
        session_id=SessionId("s1"),
        principal=Principal("client-1"),
        call_id=CallId("c1"),
        timestamp=0.0,
    )


@pytest.mark.parametrize("name", SHIPPED)
def test_every_allow_rule_carries_an_args_allowlist(name: str) -> None:
    policy = load_policy(POLICIES / name)
    unlocked = [
        rule.rule_id
        for rule in policy.rules
        if rule.enforce is Verdict.ALLOW
        and not any(check.predicate == "args_allowlist" for check in rule.checks)
    ]
    assert unlocked == []


@pytest.mark.parametrize(("name", "tool", "args"), ALLOWED_SHAPES)
def test_declared_shape_is_allowed(name: str, tool: str, args: dict[str, object]) -> None:
    decision = evaluate(call(tool, args), load_policy(POLICIES / name), SequenceState())
    assert decision.verdict is Verdict.ALLOW


@pytest.mark.parametrize(("name", "tool", "args"), ALLOWED_SHAPES)
def test_extra_argument_key_falls_through_to_default_deny(
    name: str, tool: str, args: dict[str, object]
) -> None:
    smuggled = {**args, "recursive": True}
    decision = evaluate(call(tool, smuggled), load_policy(POLICIES / name), SequenceState())
    assert decision.verdict is Verdict.DENY
