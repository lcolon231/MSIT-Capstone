"""Sequence state machine — issue #10 / T3.1 (D1).

Acceptance (issue #10):
  * `classify` advances named chains and returns DENY / GATE / None;
  * `advance(call, policy, state)` is pure, state is explicit and inspectable, transitions
    are deterministic;
  * unit tests for the transition table including duplicate / idempotent steps.

The canonical modeled chain is banking `recon_add_drain`:
    get_balance -> list_payees -> add_payee -> transfer_funds(to == added payee)
Every individual step passes per-call policy; only the *composition* is the kill chain, and
only a transfer to the just-added payee trips the blocking transition (design §4-§5).
"""

from __future__ import annotations

from src.monitor import sequence
from src.monitor.sequence import advance, classify, subject_of
from src.monitor.types import (
    CallId,
    Principal,
    SequenceState,
    SessionId,
    SubjectKey,
    ToolCall,
)
from src.policy.schema import ChainSpec, ChainStep, Check, Policy, SequenceConfig
from src.transport.contract import Verdict

# --- fixtures -----------------------------------------------------------------------------


def make_call(tool: str, *, principal: str = "acct-1", session: str = "s1", ts: float = 0.0, **args: object) -> ToolCall:
    return ToolCall(
        tool=tool,
        args=args,
        session_id=SessionId(session),
        principal=Principal(principal),
        call_id=CallId("c1"),
        timestamp=ts,
    )


def canonical_chain() -> ChainSpec:
    """The banking recon_add_drain chain, constructed directly (YAML loading lands in #12)."""
    return ChainSpec(
        name="recon_add_drain",
        domain="banking",
        steps=(
            ChainStep(trigger="get_balance", to_node="S1_BALANCE"),
            ChainStep(trigger="list_payees", from_node="S1_BALANCE", to_node="S2_PAYEES"),
            ChainStep(
                trigger="add_payee",
                from_node="S2_PAYEES",
                to_node="S3_PAYEE_ADDED",
                bind={"added_payee_id": "args.payee_id"},
            ),
            ChainStep(
                trigger="transfer_funds",
                from_node="S3_PAYEE_ADDED",
                to_node="S4_BLOCKED",
                checks=(Check(predicate="target_is_bound_payee", params={"argument": "to", "binding": "added_payee_id"}),),
                enforce=Verdict.DENY,
                rule_id="seq.recon_add_drain.terminal",
            ),
        ),
    )


def policy_with_chain() -> Policy:
    return Policy(rules=(), sequence=SequenceConfig(chains=(canonical_chain(),)))


def run_prefix(policy: Policy, *calls: ToolCall) -> SequenceState:
    """Fold `advance` over a sequence of permitted calls, starting cold."""
    state = SequenceState()
    for call in calls:
        state = advance(call, policy, state)
    return state


def node_of(state: SequenceState, call: ToolCall, chain: str = "recon_add_drain") -> str | None:
    for progress in state.for_subject(subject_of(call)):
        if progress.chain == chain:
            return progress.node
    return None


# --- subject_of ---------------------------------------------------------------------------


def test_subject_of_is_session_and_principal() -> None:
    call = make_call("get_balance", principal="acct-9", session="sX")
    assert subject_of(call) == SubjectKey(session_id=call.session_id, principal=Principal("acct-9"))


# --- advance: the transition table --------------------------------------------------------


def test_full_recon_prefix_advances_step_by_step() -> None:
    pol = policy_with_chain()
    state = SequenceState()

    state = advance(make_call("get_balance"), pol, state)
    assert node_of(state, make_call("get_balance")) == "S1_BALANCE"

    state = advance(make_call("list_payees"), pol, state)
    assert node_of(state, make_call("list_payees")) == "S2_PAYEES"

    state = advance(make_call("add_payee", payee_id="acme-1"), pol, state)
    assert node_of(state, make_call("add_payee")) == "S3_PAYEE_ADDED"


def test_add_payee_captures_a_binding_digest_not_plaintext() -> None:
    pol = policy_with_chain()
    state = run_prefix(
        pol,
        make_call("get_balance"),
        make_call("list_payees"),
        make_call("add_payee", payee_id="acme-1"),
    )
    (progress,) = state.for_subject(subject_of(make_call("add_payee")))
    assert set(progress.bindings) == {"added_payee_id"}
    digest = progress.bindings["added_payee_id"]
    assert digest != "acme-1"  # stored as a digest, never the raw identifier
    assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)


def test_out_of_order_call_does_not_advance() -> None:
    # list_payees before any get_balance is off the modeled path from S0 -> no progress.
    pol = policy_with_chain()
    state = advance(make_call("list_payees"), pol, SequenceState())
    assert state.for_subject(subject_of(make_call("list_payees"))) == ()


def test_benign_interleaved_call_neither_advances_nor_resets() -> None:
    pol = policy_with_chain()
    state = run_prefix(pol, make_call("get_balance"), make_call("list_payees"))
    # An unmatched benign tool between steps must leave S2 intact (design §7 interleaving).
    after = advance(make_call("search_docs", q="anything"), pol, state)
    assert node_of(after, make_call("get_balance")) == "S2_PAYEES"


def test_advance_is_pure_and_returns_new_state() -> None:
    pol = policy_with_chain()
    before = SequenceState()
    after = advance(make_call("get_balance"), pol, before)
    assert before.for_subject(subject_of(make_call("get_balance"))) == ()  # original untouched
    assert after is not before


def test_advance_is_deterministic() -> None:
    pol = policy_with_chain()
    calls = (make_call("get_balance"), make_call("list_payees"), make_call("add_payee", payee_id="p"))
    assert node_of(run_prefix(pol, *calls), calls[0]) == node_of(run_prefix(pol, *calls), calls[0])


def test_unmatched_call_returns_the_same_state_object() -> None:
    pol = policy_with_chain()
    state = SequenceState()
    assert advance(make_call("search_docs"), pol, state) is state


def test_no_chains_never_advances() -> None:
    empty = Policy(rules=(), sequence=SequenceConfig())
    assert advance(make_call("get_balance"), empty, SequenceState()).progress == {}


# --- advance: duplicate / idempotent steps ------------------------------------------------


def test_duplicate_add_payee_is_idempotent_and_rebinds_latest() -> None:
    pol = policy_with_chain()
    state = run_prefix(
        pol,
        make_call("get_balance"),
        make_call("list_payees"),
        make_call("add_payee", payee_id="first"),
    )
    first_digest = state.for_subject(subject_of(make_call("add_payee")))[0].bindings["added_payee_id"]

    # A repeated add_payee in S3 must stay in S3 (no off-by-one) and re-bind to the latest payee.
    state = advance(make_call("add_payee", payee_id="second"), pol, state)
    progress = state.for_subject(subject_of(make_call("add_payee")))
    assert len(progress) == 1
    assert progress[0].node == "S3_PAYEE_ADDED"
    assert progress[0].bindings["added_payee_id"] != first_digest
    assert progress[0].bindings["added_payee_id"] == sequence._canonical_digest("second")


def test_duplicate_recon_step_is_idempotent() -> None:
    pol = policy_with_chain()
    state = run_prefix(pol, make_call("get_balance"), make_call("get_balance"))
    assert node_of(state, make_call("get_balance")) == "S1_BALANCE"  # still S1, not advanced twice


# --- classify: the blocking transition ----------------------------------------------------


def test_full_kill_chain_transfer_to_bound_payee_denies() -> None:
    pol = policy_with_chain()
    state = run_prefix(
        pol,
        make_call("get_balance"),
        make_call("list_payees"),
        make_call("add_payee", payee_id="acme-1"),
    )
    decision = classify(make_call("transfer_funds", to="acme-1"), state, pol)
    assert decision is not None
    assert decision.verdict is Verdict.DENY
    assert decision.rule_id == "seq.recon_add_drain.terminal"


def test_transfer_to_different_payee_is_a_near_miss_and_falls_through() -> None:
    pol = policy_with_chain()
    state = run_prefix(
        pol,
        make_call("get_balance"),
        make_call("list_payees"),
        make_call("add_payee", payee_id="acme-1"),
    )
    # Target differs from the just-added payee -> not the modeled fraud -> None (per-call GATE).
    assert classify(make_call("transfer_funds", to="someone-else"), state, pol) is None


def test_transfer_without_full_recon_prefix_is_not_classified() -> None:
    pol = policy_with_chain()
    # add_payee then transfer with no get_balance/list_payees never reaches S3 -> None.
    state = advance(make_call("add_payee", payee_id="acme-1"), pol, SequenceState())
    assert classify(make_call("transfer_funds", to="acme-1"), state, pol) is None


def test_transfer_at_earlier_node_is_not_classified() -> None:
    pol = policy_with_chain()
    state = run_prefix(pol, make_call("get_balance"), make_call("list_payees"))  # at S2
    assert classify(make_call("transfer_funds", to="acme-1"), state, pol) is None


def test_classify_no_chains_returns_none() -> None:
    empty = Policy(rules=(), sequence=SequenceConfig())
    assert classify(make_call("transfer_funds", to="x"), SequenceState(), empty) is None


def test_classify_cold_state_returns_none() -> None:
    pol = policy_with_chain()
    assert classify(make_call("get_balance"), SequenceState(), pol) is None


def test_classify_is_read_only() -> None:
    pol = policy_with_chain()
    state = run_prefix(
        pol,
        make_call("get_balance"),
        make_call("list_payees"),
        make_call("add_payee", payee_id="acme-1"),
    )
    snapshot = state.for_subject(subject_of(make_call("add_payee")))
    classify(make_call("transfer_funds", to="acme-1"), state, pol)
    assert state.for_subject(subject_of(make_call("add_payee"))) == snapshot  # unchanged


# --- cross-subject isolation --------------------------------------------------------------


def test_progress_is_isolated_per_subject() -> None:
    pol = policy_with_chain()
    # Principal A completes the recon+add prefix; principal B does nothing.
    state = run_prefix(
        pol,
        make_call("get_balance", principal="A"),
        make_call("list_payees", principal="A"),
        make_call("add_payee", principal="A", payee_id="acme-1"),
    )
    # B transferring to that payee id is NOT on B's (empty) chain.
    assert classify(make_call("transfer_funds", principal="B", to="acme-1"), state, pol) is None
    # A transferring to it still trips.
    assert classify(make_call("transfer_funds", principal="A", to="acme-1"), state, pol).verdict is Verdict.DENY


# --- escalating (GATE) step support -------------------------------------------------------


def test_escalating_step_can_emit_gate() -> None:
    # A modeled chain may declare an escalating step with enforce: GATE; classify surfaces it.
    chain = ChainSpec(
        name="probe_then_gate",
        domain="banking",
        steps=(
            ChainStep(trigger="get_balance", to_node="P1"),
            ChainStep(trigger="list_payees", from_node="P1", to_node="P2", enforce=Verdict.GATE, rule_id="seq.probe.gate"),
        ),
    )
    pol = Policy(rules=(), sequence=SequenceConfig(chains=(chain,)))
    state = advance(make_call("get_balance"), pol, SequenceState())
    decision = classify(make_call("list_payees"), state, pol)
    assert decision is not None and decision.verdict is Verdict.GATE
    assert decision.rule_id == "seq.probe.gate"
