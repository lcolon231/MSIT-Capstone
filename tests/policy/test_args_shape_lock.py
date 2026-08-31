"""Per-call argument shape-locking (issue #57), end-to-end through the loader and evaluate().

`args_allowlist` is the equivalent of JSON Schema's ``additionalProperties: false``: an ALLOW
rule that carries it stops matching the moment a call brings an argument key the policy author did
not declare, so the call falls through to the fail-closed default DENY. A missing/malformed
``allowed`` config is itself fail-closed (the predicate raises, which counts as a non-match).
"""

from __future__ import annotations

from typing import Any

from src.monitor.types import CallId, Principal, SequenceState, SessionId, ToolCall
from src.monitor.verdict import evaluate
from src.policy.loader import validate_policy
from src.policy.schema import Policy
from src.transport.contract import Verdict


def call(tool: str, **args: object) -> ToolCall:
    return ToolCall(
        tool=tool,
        args=args,
        session_id=SessionId("s1"),
        principal=Principal("client-1"),
        call_id=CallId("c1"),
        timestamp=0.0,
    )


def shape_locked_policy(params: dict[str, Any]) -> Policy:
    """An ALLOW rule for `read_file` shape-locked by `args_allowlist` with the given params —
    built through the real loader so the check parses exactly as a YAML policy would."""
    return validate_policy(
        {
            "rules": [
                {
                    "rule_id": "read.allow",
                    "tool": "read_file",
                    "trigger": "action",
                    "enforce": "allow",
                    "checks": [{"predicate": "args_allowlist", "params": params}],
                }
            ]
        }
    )


def test_declared_keys_are_allowed() -> None:
    policy = shape_locked_policy({"allowed": ["path"]})
    decision = evaluate(call("read_file", path="/tmp/report.txt"), policy, SequenceState())
    assert decision.verdict is Verdict.ALLOW
    assert decision.rule_id == "read.allow"


def test_unexpected_key_falls_through_to_default_deny() -> None:
    policy = shape_locked_policy({"allowed": ["path"]})
    decision = evaluate(
        call("read_file", path="/tmp/report.txt", follow_symlinks=True), policy, SequenceState()
    )
    assert decision.verdict is Verdict.DENY
    assert decision.rule_id == "default"


def test_missing_allowed_config_is_fail_closed_deny() -> None:
    # 'allowed' omitted: the predicate raises, _check_holds catches it as a non-match, and the
    # call reaches the default DENY — a misconfigured shape lock never fails open.
    policy = shape_locked_policy({})
    decision = evaluate(call("read_file", path="/tmp/report.txt"), policy, SequenceState())
    assert decision.verdict is Verdict.DENY
    assert decision.rule_id == "default"
