"""Sequence state machine — issue #10 / T3.1 (D1).

Acceptance (issue #10):
  * `classify` advances named chains and returns DENY / GATE / None;
  * `advance(call, policy, state)` is pure, state is explicit and inspectable, transitions
    are deterministic;
  * unit tests for the transition table including duplicate / idempotent steps.

The canonical modeled chain is RMM `recon_register_exfil`:
    list_endpoints -> list_shares -> register_destination -> export_records(to == added destination)
Every individual step passes per-call policy; only the *composition* is the kill chain, and
only a export to the just-registered destination trips the blocking transition (design §4-§5).
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


def make_call(tool: str, *, principal: str = "client-1", session: str = "s1", ts: float = 0.0, **args: object) -> ToolCall:
    return ToolCall(
        tool=tool,
        args=args,
        session_id=SessionId(session),
        principal=Principal(principal),
        call_id=CallId("c1"),
        timestamp=ts,
    )


def canonical_chain() -> ChainSpec:
    """The RMM recon_register_exfil chain, constructed directly (YAML loading lands in #12)."""
    return ChainSpec(
        name="recon_register_exfil",
        domain="rmm",
        steps=(
            ChainStep(trigger="list_endpoints", to_node="S1_ENDPOINTS"),
            ChainStep(trigger="list_shares", from_node="S1_ENDPOINTS", to_node="S2_SHARES"),
            ChainStep(
                trigger="register_destination",
                from_node="S2_SHARES",
                to_node="S3_DESTINATION_ADDED",
                bind={"registered_destination": "args.destination"},
            ),
            ChainStep(
                trigger="export_records",
                from_node="S3_DESTINATION_ADDED",
                to_node="S4_BLOCKED",
                checks=(Check(predicate="target_is_bound_value", params={"argument": "to", "binding": "registered_destination"}),),
                enforce=Verdict.DENY,
                rule_id="seq.recon_register_exfil.terminal",
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


def node_of(state: SequenceState, call: ToolCall, chain: str = "recon_register_exfil") -> str | None:
    for progress in state.for_subject(subject_of(call)):
        if progress.chain == chain:
            return progress.node
    return None


# --- subject_of ---------------------------------------------------------------------------


def test_subject_of_is_session_and_principal() -> None:
    call = make_call("list_endpoints", principal="client-9", session="sX")
    assert subject_of(call) == SubjectKey(session_id=call.session_id, principal=Principal("client-9"))


# --- advance: the transition table --------------------------------------------------------


def test_full_recon_prefix_advances_step_by_step() -> None:
    pol = policy_with_chain()
    state = SequenceState()

    state = advance(make_call("list_endpoints"), pol, state)
    assert node_of(state, make_call("list_endpoints")) == "S1_ENDPOINTS"

    state = advance(make_call("list_shares"), pol, state)
    assert node_of(state, make_call("list_shares")) == "S2_SHARES"

    state = advance(make_call("register_destination", destination="acme-1"), pol, state)
    assert node_of(state, make_call("register_destination")) == "S3_DESTINATION_ADDED"


def test_register_destination_captures_a_binding_digest_not_plaintext() -> None:
    pol = policy_with_chain()
    state = run_prefix(
        pol,
        make_call("list_endpoints"),
        make_call("list_shares"),
        make_call("register_destination", destination="acme-1"),
    )
    (progress,) = state.for_subject(subject_of(make_call("register_destination")))
    assert set(progress.bindings) == {"registered_destination"}
    digest = progress.bindings["registered_destination"]
    assert digest != "acme-1"  # stored as a digest, never the raw identifier
    assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)


def test_out_of_order_call_does_not_advance() -> None:
    # list_shares before any list_endpoints is off the modeled path from S0 -> no progress.
    pol = policy_with_chain()
    state = advance(make_call("list_shares"), pol, SequenceState())
    assert state.for_subject(subject_of(make_call("list_shares"))) == ()


def test_benign_interleaved_call_neither_advances_nor_resets() -> None:
    pol = policy_with_chain()
    state = run_prefix(pol, make_call("list_endpoints"), make_call("list_shares"))
    # An unmatched benign tool between steps must leave S2 intact (design §7 interleaving).
    after = advance(make_call("search_docs", q="anything"), pol, state)
    assert node_of(after, make_call("list_endpoints")) == "S2_SHARES"


def test_advance_is_pure_and_returns_new_state() -> None:
    pol = policy_with_chain()
    before = SequenceState()
    after = advance(make_call("list_endpoints"), pol, before)
    assert before.for_subject(subject_of(make_call("list_endpoints"))) == ()  # original untouched
    assert after is not before


def test_advance_is_deterministic() -> None:
    pol = policy_with_chain()
    calls = (make_call("list_endpoints"), make_call("list_shares"), make_call("register_destination", destination="p"))
    assert node_of(run_prefix(pol, *calls), calls[0]) == node_of(run_prefix(pol, *calls), calls[0])


def test_unmatched_call_returns_the_same_state_object() -> None:
    pol = policy_with_chain()
    state = SequenceState()
    assert advance(make_call("search_docs"), pol, state) is state


def test_no_chains_never_advances() -> None:
    empty = Policy(rules=(), sequence=SequenceConfig())
    assert advance(make_call("list_endpoints"), empty, SequenceState()).progress == {}


# --- advance: duplicate / idempotent steps ------------------------------------------------


def test_duplicate_register_destination_is_idempotent_and_rebinds_latest() -> None:
    pol = policy_with_chain()
    state = run_prefix(
        pol,
        make_call("list_endpoints"),
        make_call("list_shares"),
        make_call("register_destination", destination="first"),
    )
    first_digest = state.for_subject(subject_of(make_call("register_destination")))[0].bindings["registered_destination"]

    # A repeated register_destination in S3 must stay in S3 (no off-by-one) and re-bind to the latest destination.
    state = advance(make_call("register_destination", destination="second"), pol, state)
    progress = state.for_subject(subject_of(make_call("register_destination")))
    assert len(progress) == 1
    assert progress[0].node == "S3_DESTINATION_ADDED"
    assert progress[0].bindings["registered_destination"] != first_digest
    assert progress[0].bindings["registered_destination"] == sequence._canonical_digest("second")


def test_duplicate_recon_step_is_idempotent() -> None:
    pol = policy_with_chain()
    state = run_prefix(pol, make_call("list_endpoints"), make_call("list_endpoints"))
    assert node_of(state, make_call("list_endpoints")) == "S1_ENDPOINTS"  # still S1, not advanced twice


# --- classify: the blocking transition ----------------------------------------------------


def test_full_kill_chain_transfer_to_bound_destination_denies() -> None:
    pol = policy_with_chain()
    state = run_prefix(
        pol,
        make_call("list_endpoints"),
        make_call("list_shares"),
        make_call("register_destination", destination="acme-1"),
    )
    decision = classify(make_call("export_records", to="acme-1"), state, pol)
    assert decision is not None
    assert decision.verdict is Verdict.DENY
    assert decision.rule_id == "seq.recon_register_exfil.terminal"


def test_export_to_different_destination_is_a_near_miss_and_falls_through() -> None:
    pol = policy_with_chain()
    state = run_prefix(
        pol,
        make_call("list_endpoints"),
        make_call("list_shares"),
        make_call("register_destination", destination="acme-1"),
    )
    # Target differs from the just-registered destination -> not the modeled fraud -> None (per-call GATE).
    assert classify(make_call("export_records", to="someone-else"), state, pol) is None


def test_transfer_without_full_recon_prefix_is_not_classified() -> None:
    pol = policy_with_chain()
    # register_destination then transfer with no list_endpoints/list_shares never reaches S3 -> None.
    state = advance(make_call("register_destination", destination="acme-1"), pol, SequenceState())
    assert classify(make_call("export_records", to="acme-1"), state, pol) is None


def test_transfer_at_earlier_node_is_not_classified() -> None:
    pol = policy_with_chain()
    state = run_prefix(pol, make_call("list_endpoints"), make_call("list_shares"))  # at S2
    assert classify(make_call("export_records", to="acme-1"), state, pol) is None


def test_classify_no_chains_returns_none() -> None:
    empty = Policy(rules=(), sequence=SequenceConfig())
    assert classify(make_call("export_records", to="x"), SequenceState(), empty) is None


def test_classify_cold_state_returns_none() -> None:
    pol = policy_with_chain()
    assert classify(make_call("list_endpoints"), SequenceState(), pol) is None


def test_classify_is_read_only() -> None:
    pol = policy_with_chain()
    state = run_prefix(
        pol,
        make_call("list_endpoints"),
        make_call("list_shares"),
        make_call("register_destination", destination="acme-1"),
    )
    snapshot = state.for_subject(subject_of(make_call("register_destination")))
    classify(make_call("export_records", to="acme-1"), state, pol)
    assert state.for_subject(subject_of(make_call("register_destination"))) == snapshot  # unchanged


# --- cross-subject isolation --------------------------------------------------------------


def test_progress_is_isolated_per_subject() -> None:
    pol = policy_with_chain()
    # Principal A completes the recon+add prefix; principal B does nothing.
    state = run_prefix(
        pol,
        make_call("list_endpoints", principal="A"),
        make_call("list_shares", principal="A"),
        make_call("register_destination", principal="A", destination="acme-1"),
    )
    # B transferring to that destination id is NOT on B's (empty) chain.
    assert classify(make_call("export_records", principal="B", to="acme-1"), state, pol) is None
    # A transferring to it still trips.
    assert classify(make_call("export_records", principal="A", to="acme-1"), state, pol).verdict is Verdict.DENY


# --- escalating (GATE) step support -------------------------------------------------------


def test_escalating_step_can_emit_gate() -> None:
    # A modeled chain may declare an escalating step with enforce: GATE; classify surfaces it.
    chain = ChainSpec(
        name="probe_then_gate",
        domain="rmm",
        steps=(
            ChainStep(trigger="list_endpoints", to_node="P1"),
            ChainStep(trigger="list_shares", from_node="P1", to_node="P2", enforce=Verdict.GATE, rule_id="seq.probe.gate"),
        ),
    )
    pol = Policy(rules=(), sequence=SequenceConfig(chains=(chain,)))
    state = advance(make_call("list_endpoints"), pol, SequenceState())
    decision = classify(make_call("list_shares"), state, pol)
    assert decision is not None and decision.verdict is Verdict.GATE
    assert decision.rule_id == "seq.probe.gate"
