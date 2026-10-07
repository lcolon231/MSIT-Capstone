"""Policy edge cases that must never produce ALLOW (spec.md §8 #2, interface-contracts.md §1.2).

Each case below must end in either a load-time `PolicyError` or a `DENY` verdict from the pure
`evaluate` — never ALLOW:
  * an empty policy set;
  * malformed YAML / structurally invalid documents;
  * an unknown tool;
  * argument values whose type does not match what the tool/predicate expects;
  * rule-precedence conflicts (two rules for one tool that disagree).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.monitor.types import CallId, Principal, SequenceState, SessionId, ToolCall
from src.monitor.verdict import evaluate
from src.policy.loader import PolicyError, load_policy, validate_policy
from src.policy.schema import Policy
from src.transport.contract import Verdict

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICIES = REPO_ROOT / "policies"


def make_call(tool: str, **args: object) -> ToolCall:
    return ToolCall(
        tool=tool,
        args=args,
        session_id=SessionId("s1"),
        principal=Principal("client-1"),
        call_id=CallId("c1"),
        timestamp=0.0,
    )


# --- empty policy set ---------------------------------------------------------------------


@pytest.mark.parametrize("document", [{}, {"rules": []}, {"rules": None}, {"sequence": None}])
def test_validate_policy_empty_document_denies_every_call(document: dict[str, object]) -> None:
    policy = validate_policy(document)
    decision = evaluate(make_call("list_endpoints"), policy, SequenceState())
    assert decision.verdict is Verdict.DENY
    assert decision.rule_id == "default"


def test_load_policy_empty_file_is_rejected(tmp_path: Path) -> None:
    # An empty YAML file parses to None — not a mapping, so it must not load as "allow all".
    path = tmp_path / "empty.yaml"
    path.write_text("", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(path)


def test_deny_all_policy_denies_every_known_tool() -> None:
    policy = Policy.deny_all()
    for tool in ("list_endpoints", "list_shares", "read_file", "fetch_url"):
        assert evaluate(make_call(tool), policy, SequenceState()).verdict is Verdict.DENY


# --- malformed YAML / malformed structure ---------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "rules: [unclosed",
        "rules:\n  - rule_id: a\n   tool: b",  # bad indentation
        "- just\n- a\n- list\n",
        "a scalar",
        "rules: not-a-list",
        "rules:\n  - not-a-mapping",
        "rules:\n  - {rule_id: r, tool: t, trigger: action}",  # missing enforce
        "rules:\n  - {rule_id: r, tool: t, trigger: action, enforce: maybe}",
        "rules:\n  - {rule_id: r, tool: t, trigger: whenever, enforce: allow}",
        "rules:\n  - {rule_id: r, tool: t, trigger: action, enforce: allow, checks: oops}",
        "rules:\n  - {rule_id: r, tool: t, trigger: action, enforce: allow, checks: [{}]}",
        "rules:\n  - {rule_id: r, tool: t, trigger: action, enforce: allow,"
        " checks: [{predicate: arg_equals, params: [1]}]}",
        "rules:\n  - {rule_id: r, tool: t, trigger: action, enforce: allow, extra: 1}",
        "sequence: []",
        "sequence: {chains: [{name: c, domain: d, steps: []}]}",
        "sequence: {chains: [{name: c, domain: d}]}",
        "sequence: {chains: [{name: c, domain: d, steps: [{to: S1}]}]}",
        "sequence: {chains: [{name: '', domain: d, steps: [{trigger: t, to: S1}]}]}",
        "sequence: {chains: [{name: c, domain: d, steps: [{trigger: t, to: S1, from: S0}]}]}",
        "sequence: {chains: [{name: c, domain: d, steps: [{trigger: t, to: S1, enforce: deny}]}]}",
        "sequence: {chains: [{name: c, domain: d, steps: [{trigger: t, to: S1, bind: [x]}]}]}",
        "sequence: {chains: [{name: c, domain: d, steps: [{trigger: t, to: S1}]},"
        " {name: c, domain: d, steps: [{trigger: t, to: S1}]}]}",
    ],
)
def test_load_policy_malformed_document_raises_policy_error(tmp_path: Path, text: str) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(path)


# --- unknown tool -------------------------------------------------------------------------


@pytest.mark.parametrize("policy_file", sorted(p.name for p in POLICIES.glob("*.yaml")))
@pytest.mark.parametrize("tool", ["wire_to_offshore", "", "LIST_ENDPOINTS", "list_endpoints "])
def test_evaluate_unknown_tool_under_every_shipped_policy_denies(
    policy_file: str, tool: str
) -> None:
    decision = evaluate(make_call(tool), load_policy(POLICIES / policy_file), SequenceState())
    assert decision.verdict is Verdict.DENY


# --- argument types that do not match the expected shape ----------------------------------
#
# A predicate that receives the wrong type must count as "check failed" — and the overall
# verdict for that call must not be ALLOW (interface-contracts.md §1.2: "invalid arguments ...
# never become ALLOW").


@pytest.mark.parametrize(
    "command",
    [
        ["rm", "-rf", "/"],
        {"cmd": "rm -rf /"},
        b"rm -rf /",
        None,
        42,
    ],
    ids=["list", "dict", "bytes", "none", "int"],
)
def test_evaluate_shell_command_with_non_string_type_is_not_allowed(command: object) -> None:
    policy = load_policy(POLICIES / "shell.yaml")
    decision = evaluate(make_call("shell", command=command), policy, SequenceState())
    assert decision.verdict is not Verdict.ALLOW


@pytest.mark.parametrize(
    "args",
    [
        {"command": ["rm", "-rf", "/"]},
        {"command": None},
        {},
        {"cmd": "rm -rf /"},
        {"command": "ls", "extra": "x"},
    ],
    ids=["list", "none", "absent", "wrong-key", "extra-key"],
)
def test_evaluate_shell_allow_is_shape_locked_even_without_deny_rule(
    monkeypatch: pytest.MonkeyPatch, args: dict[str, object]
) -> None:
    # Defense in depth: neutralize the deny predicate entirely; the allow rule's own shape lock
    # must still refuse malformed calls, falling through to the default DENY.
    from src.policy import predicates

    monkeypatch.setitem(predicates.REGISTRY, "is_destructive_cmd", lambda call, params: False)
    policy = load_policy(POLICIES / "shell.yaml")
    decision = evaluate(make_call("shell", **args), policy, SequenceState())
    assert decision.verdict is Verdict.DENY
    assert decision.rule_id == "default"


def test_evaluate_shell_benign_string_command_still_allows() -> None:
    policy = load_policy(POLICIES / "shell.yaml")
    decision = evaluate(make_call("shell", command="ls -la"), policy, SequenceState())
    assert decision.verdict is Verdict.ALLOW
    assert decision.rule_id == "shell.allow"


@pytest.mark.parametrize(
    "to",
    [["alice@example.com"], {"addr": "alice@example.com"}, None, 7, b"alice@example.com"],
    ids=["list", "dict", "none", "int", "bytes"],
)
def test_evaluate_email_recipient_with_non_string_type_denies(to: object) -> None:
    policy = load_policy(POLICIES / "email.yaml")
    decision = evaluate(make_call("send_email", to=to), policy, SequenceState())
    assert decision.verdict is Verdict.DENY


@pytest.mark.parametrize(
    ("predicate", "params"),
    [
        ("arg_equals", {}),  # missing 'arg' -> KeyError inside the predicate
        ("args_allowlist", {"allowed": "path"}),  # bare string, not a list
        ("args_allowlist", {}),
        ("arg_matches", {"arg": "x"}),  # missing 'pattern'
        ("arg_matches", {"arg": "x", "pattern": "("}),  # invalid regex
    ],
)
def test_evaluate_allow_rule_with_erroring_predicate_denies(
    predicate: str, params: dict[str, object]
) -> None:
    policy = validate_policy(
        {
            "rules": [
                {
                    "rule_id": "t.allow",
                    "tool": "t",
                    "trigger": "action",
                    "enforce": "allow",
                    "checks": [{"predicate": predicate, "params": params}],
                }
            ]
        }
    )
    assert evaluate(make_call("t", x="v"), policy, SequenceState()).verdict is Verdict.DENY


def test_evaluate_negated_check_with_erroring_predicate_still_denies() -> None:
    # Negation must not flip an erroring predicate into a match.
    policy = validate_policy(
        {
            "rules": [
                {
                    "rule_id": "t.allow",
                    "tool": "t",
                    "trigger": "action",
                    "enforce": "allow",
                    "checks": [{"predicate": "arg_equals", "params": {}, "negate": True}],
                }
            ]
        }
    )
    assert evaluate(make_call("t"), policy, SequenceState()).verdict is Verdict.DENY


# --- rule-precedence conflicts ------------------------------------------------------------


def _two_rules(first: str, second: str) -> Policy:
    return validate_policy(
        {
            "rules": [
                {"rule_id": f"t.{first}.1", "tool": "t", "trigger": "action", "enforce": first},
                {"rule_id": f"t.{second}.2", "tool": "t", "trigger": "action", "enforce": second},
            ]
        }
    )


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        ("deny", "allow", Verdict.DENY),
        ("gate", "allow", Verdict.GATE),
        ("deny", "gate", Verdict.DENY),
    ],
)
def test_evaluate_conflicting_rules_stricter_rule_listed_first_wins(
    first: str, second: str, expected: Verdict
) -> None:
    decision = evaluate(make_call("t"), _two_rules(first, second), SequenceState())
    assert decision.verdict is expected
    assert decision.rule_id == f"t.{first}.1"


def test_evaluate_conflicting_rules_resolution_is_first_match_and_traceable() -> None:
    # Documented semantics (interface-contracts.md §4.5): first-match. The winning rule is
    # always identifiable from the Decision's rule_id, whichever order the author used.
    decision = evaluate(make_call("t"), _two_rules("allow", "deny"), SequenceState())
    assert decision.rule_id == "t.allow.1"


def test_evaluate_sequence_deny_overrides_per_call_allow_on_conflict() -> None:
    # The sequence layer only ever tightens: a chain DENY beats a per-call ALLOW for the
    # same call (verdict.py "stricter of").
    from src.monitor.sequence import _canonical_digest
    from src.monitor.types import ChainProgress, SubjectKey

    policy = validate_policy(
        {
            "rules": [{"rule_id": "x.allow", "tool": "x", "trigger": "action", "enforce": "allow"}],
            "sequence": {
                "chains": [
                    {
                        "name": "c",
                        "domain": "d",
                        "steps": [
                            {"trigger": "w", "to": "S1", "bind": {"b": "args.v"}},
                            {
                                "trigger": "x",
                                "from": "S1",
                                "to": "S2",
                                "checks": [
                                    {
                                        "predicate": "target_is_bound_value",
                                        "params": {"argument": "v", "binding": "b"},
                                    }
                                ],
                                "enforce": "deny",
                                "rule_id": "seq.c.terminal",
                            },
                        ],
                    }
                ]
            },
        }
    )
    key = SubjectKey(SessionId("s1"), Principal("client-1"))
    state = SequenceState(
        progress={
            key: (ChainProgress(chain="c", node="S1", bindings={"b": _canonical_digest("z")}),)
        }
    )
    decision = evaluate(make_call("x", v="z"), policy, state)
    assert decision.verdict is Verdict.DENY
    assert decision.rule_id == "seq.c.terminal"


# --- load errors are always PolicyError (loader contract: "Raises PolicyError on any problem") ---


@pytest.mark.parametrize(
    "raw",
    [b"\x00\xff\xfe rules: [", b"\xff\xfe\x00\x00", "rules: []".encode("utf-16")],
    ids=["binary", "bad-bom", "utf-16"],
)
def test_load_policy_non_utf8_bytes_raise_policy_error(tmp_path: Path, raw: bytes) -> None:
    path = tmp_path / "binary.yaml"
    path.write_bytes(raw)
    with pytest.raises(PolicyError):
        load_policy(path)
