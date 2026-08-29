"""Argument-aware matching through pure evaluate() (issue #8 / T2.5, criterion #3).

End-to-end over the real policies/shell.yaml and policies/email.yaml: a benign shell command
is ALLOWed, a destructive one (and its ${IFS} evasion) is DENYed by the explicit rule, and a
look-alike email domain fails closed to the default DENY.
"""

from __future__ import annotations

from pathlib import Path

from src.monitor.types import CallId, Principal, SequenceState, SessionId, ToolCall
from src.monitor.verdict import evaluate
from src.policy.loader import load_policy
from src.transport.contract import Verdict

REPO_ROOT = Path(__file__).resolve().parents[2]
SHELL = REPO_ROOT / "policies" / "shell.yaml"
EMAIL = REPO_ROOT / "policies" / "email.yaml"


def call(tool: str, **args: object) -> ToolCall:
    return ToolCall(
        tool=tool,
        args=args,
        session_id=SessionId("s1"),
        principal=Principal("client-1"),
        call_id=CallId("c1"),
        timestamp=0.0,
    )


def test_shell_allows_benign_command() -> None:
    d = evaluate(call("shell", command="ls -la"), load_policy(SHELL), SequenceState())
    assert d.verdict is Verdict.ALLOW
    assert d.rule_id == "shell.allow"


def test_shell_denies_destructive_command() -> None:
    d = evaluate(call("shell", command="rm -rf /"), load_policy(SHELL), SequenceState())
    assert d.verdict is Verdict.DENY
    assert d.rule_id == "shell.destructive.deny"


def test_shell_denies_ifs_evasion() -> None:
    d = evaluate(call("shell", command="rm${IFS}-rf${IFS}/"), load_policy(SHELL), SequenceState())
    assert d.verdict is Verdict.DENY
    assert d.rule_id == "shell.destructive.deny"


def test_email_allows_approved_domain() -> None:
    d = evaluate(call("send_email", to="ops@example.com"), load_policy(EMAIL), SequenceState())
    assert d.verdict is Verdict.ALLOW


def test_email_denies_lookalike_domain_fail_closed() -> None:
    d = evaluate(
        call("send_email", to="attacker@example.com.evil.com"),
        load_policy(EMAIL),
        SequenceState(),
    )
    assert d.verdict is Verdict.DENY
    assert d.rule_id == "default"
