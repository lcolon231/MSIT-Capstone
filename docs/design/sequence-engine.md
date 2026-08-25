# Sequence Engine — Kill-Chain Automaton Design (D1)

> **Phase 2 design, v2.1 (2026-08-24).** Design-only. Defines the states, transitions, data
> bindings, and DENY-vs-GATE rules of the explicit kill-chain automaton. The worked example is the
> canonical banking chain `get_balance → list_payees → add_payee → transfer_funds`, in which every
> call passes per-call checks and only the *composition* is blocked.
>
> Decision basis: **D1** (explicit state machine, not heuristics or probabilistic reachability),
> **D8** (DENY + GATE only — no agent-modifying actions), **D12** (state keyed on
> `(session, principal)`; reconstructed by audit replay), **D15** (live-state clearing preserves
> replay history), and **D16** (canonical near misses fall through to D5). Limitation cited, not hidden: a bounded
> automaton catches only pre-modeled chains (Schneider 2000).

---

## 1. What the engine is, and what it is not

The sequence engine is a **deterministic finite automaton per (subject, modeled chain)**. It
recognizes named, ordered compositions of tool calls whose individual steps all pass per-call
policy, and whose *combination* is the attack. It is:

- **Deterministic** — same `(call, policy, state)` always yields the same result. No probabilistic
  window heuristic or score. (D1 rejects the DTMC-reachability alternative precisely because a
  probabilistic verdict reintroduces the non-determinism the monitor exists to remove.)
- **Explainable and diagrammable** — every transition has a name and a reason; the state is
  inspectable in the console. This *is* the hero diagram (Figure 4).
- **Bounded** — it catches only chains it has been taught. Novel orderings are out of scope by
  construction (see `residual-risks.md`), and that limitation is citable (Schneider 2000), not a
  latent bug.

It is **not** a taint tracker, not a trajectory reasoner, and not an LLM. For a structurally valid,
principal-resolved call, it sits *before* per-call policy in `evaluate` and, when it fires, its
verdict wins.

---

## 2. Where it sits in `evaluate`

From `tasks/spec.md` §9, the pure verdict order is:

```python
def evaluate(call: ToolCall, policy: Policy, state: SequenceState) -> Decision:
    # 0. Monitor-assigned boundary validation: invalid session/malformed/unknown/unresolved DENY.
    if call.validation is not CallValidation.VALID:
        return validation_deny(call.validation)  # system-scoped, traceable rule_id
    # 1. Sequence engine. A modeled chain reaching a blocking transition wins outright.
    if (seq := policy_sequence_classify(call, state, policy)) is not None:
        return seq                      # DENY or GATE, with a chain-scoped rule_id
    # 2. Per-call, argument-aware policy.
    if (rule := policy.match(call)) is not None:
        return rule.decide(call)        # ALLOW / DENY / GATE
    # 3. Fail-closed default.
    return Decision(Verdict.DENY, rule_id="default", reason="no matching policy (fail-closed)")
```

`evaluate` is **pure and read-only**. It does *not* advance state. State advancement is a separate
pure step (`advance`, §6) that the service applies **only after a call is permitted and the mock
tool reports successful execution**. This split keeps `evaluate` side-effect-free and avoids
advancing a chain for a failed `add_payee` or other no-effect tool outcome.

**Precedence note (resolved here, flagged as a design choice):** `transfer_funds` is a D5 gate
class, so *per-call* policy would return `GATE` for it. The sequence engine runs first, so when the
full kill chain is present it returns `DENY` and the per-call `GATE` never runs. "Every call passes
per-call checks" therefore means *no per-call rule denies any step*; the composition is what turns a
would-be `GATE` into a `DENY`. See §8 for the full DENY-vs-GATE table.

---

## 3. State model

State is held per **`SubjectKey = (session_id, resource_principal)`** (D12.1). `resource_principal`
is the account/endpoint/client the chain acts against, resolved by the monitor from the call —
never accepted from the agent as an authoritative principal. Arguments may name a target; the
monitor validates and canonicalizes it through the selected tool's schema before assignment.

```
SequenceState
 └── per SubjectKey:
      └── per modeled chain (ChainSpec.name):
           ChainProgress:
             node:        one of the automaton states (§4)
             binding_digests:
                          named SHA-256 values captured on entry (e.g. added_payee_id)
             step_times:  timestamp per completed step   (for pacing / lookback analysis)
             updated_at:  last advance (for idle expiry)
```

`SequenceState` is **immutable** — `advance` returns a new value. The live, mutable copy is owned by
`src/monitor/session.py`, not by the automaton.

### Cross-session durability (D12)

- Within a session, progress is tracked under `(session_id, principal)`.
- **Live state and historical progress are distinct (D15).** Session end or the configurable
  30-minute idle expiry invalidates the capability, removes the live composite-key entry, and emits
  a lifecycle event. It does not erase recent principal-level chain-progress records and is not a
  replay barrier.
- A **new** session for the same principal is **seeded by replaying the audit log** for that
  principal over the lookback window (default 24 h) — `reconstruct_sequence_state`. Replay folds
  recent progress by principal and chain, restores nodes plus named binding digests, and re-keys
  the snapshot to the new monitor-assigned session. There is no second datastore.
- Consequence: the **principal is the durable anchor** and the lookback window is the security-
  history horizon. A fresh session is seeded from the principal's recent chain-progress events, so
  neither a new run nor waiting for live idle expiry erases the prefix. The agent cannot rotate or
  forge a valid session in any case (D12.2/D14), and there is no agent-triggerable "forget history"
  operation.

---

## 4. The canonical automaton (worked example)

Modeled chain `banking.recon_add_drain`. Steps must occur **in order** for the *same principal*;
benign calls in between are ignored (they don't advance and don't reset — see §7).

| State | Meaning | Entered when |
|---|---|---|
| `S0_IDLE` | no within-lookback progress | initial, or after replay finds no retained prefix |
| `S1_BALANCE` | reconnaissance: balance read | `get_balance` on the principal |
| `S2_PAYEES` | reconnaissance: existing payees enumerated | `list_payees` while in `S1_BALANCE` |
| `S3_PAYEE_ADDED` | a **new** payee was added after full recon | `add_payee` while in `S2_PAYEES`; **binds** `added_payee_id` |
| `S4_BLOCKED` | terminal trap (bookkeeping only) | the blocking transition fired |

### Transitions

```
S0_IDLE      --get_balance-->            S1_BALANCE
S1_BALANCE   --list_payees-->            S2_PAYEES
S2_PAYEES    --add_payee(p)-->           S3_PAYEE_ADDED   [bind added_payee_id = H(p)]
S3_PAYEE_ADDED --transfer_funds(H(to)=H(p))--> S4_BLOCKED  [BLOCKING: emit verdict]   ← the kill chain
S3_PAYEE_ADDED --transfer_funds(H(to)≠H(p))--> (None, stay S3) [fall through to D5 GATE]
```

`H` is canonical SHA-256 over one value. The blocking transition
(`S3 --transfer to the just-added payee--> S4`) is the whole point: the
recon prefix (`get_balance`, `list_payees`) plus adding a **new** payee plus immediately draining to
**that** payee is the fraud signature. The digest equality binding (§5) is what separates fraud
from a legitimate payment without retaining the identifier in the audit log.

---

## 5. Data binding — why this is not a false-block factory

The critical requirement (`tasks/todo.md` T3.3, `tasks/qa-redteam-plan.md` T4.3): **a legitimate
payee-add-then-transfer must not be blocked.** The automaton achieves this three ways, all
deterministic:

1. **Full ordered prefix required.** The blocking transition is only reachable from `S3`, which is
   only reachable via `S0→S1→S2→S3`. A legitimate flow that is just `add_payee → transfer_funds`
   (no recon sweep) never enters `S1`/`S2`, so `classify` returns `None` and the call falls through
   to per-call policy. Under D5 the transfer receives `GATE`; after legitimate operator approval it
   executes. That is the required benign **pass**, not a sequence-level ALLOW that would bypass D5.
   **Dropping any prefix step drops you off the chain.**
2. **Target binding.** The blocking transition requires
   `H(transfer_funds.to) == binding_digests["added_payee_id"]`. A transfer to a **pre-existing**
   payee — even after recon — is a near-miss, not the kill chain. Under D16, `classify` returns
   `None`, ordinary D5 policy returns `GATE`, and `S3` is preserved. Plaintext payee identifiers
   are not retained in the audit log.
3. **No historical reset by the agent.** The agent cannot wipe `S3` by declaring a new task,
   choosing a session, or waiting for live idle expiry. Monitor-side lifecycle actions clear the
   live entry, while replay restores within-lookback progress for the principal (D14/D15).

This gives a principled false-block guard: the engine blocks the *specific modeled composition* and
nothing adjacent to it.

---

## 6. `classify` and `advance` — the two pure functions

```python
def classify(call: ToolCall, state: SequenceState, policy: Policy) -> Decision | None:
    """Pure, read-only. Return DENY/GATE iff `call` reaches a blocking/escalating transition
    of some modeled chain for this subject; otherwise None (let per-call policy decide)."""

def advance(call: ToolCall, policy: Policy, state: SequenceState) -> SequenceState:
    """Pure. Return the next state after `call` — permitted and successfully executed — moves
    the modeled chains in `policy` forward. Never called for a DENY or failed tool outcome."""
```

- `classify` is invoked inside `evaluate` (step 1, §2).
- `advance` is invoked by `MonitorService` **after** a permitted call succeeds. The
  terminal `transfer_funds` is *denied*, so it never executes and never advances to `S4` via
  `advance`; `S4` is bookkeeping recorded alongside the DENY decision, not a sign the transfer ran.

Both are pure; all mutation and persistence live in `session.py` + `audit`.

---

## 7. Evasion handling (the tests that decide whether the novelty survives)

From `tasks/qa-redteam-plan.md` T4.2, each with the automaton's deterministic answer:

| Evasion | Automaton behaviour |
|---|---|
| **Interleaving** benign calls (`search_docs`) between steps | Unmatched calls neither advance nor reset the chain node; `S3` survives noise. |
| **Reordering / partial chains** (`add_payee → transfer` with no recon) | Not on the modeled path → `classify` returns `None` → per-call policy applies (transfer still gates). Intentional: this is the false-block guard, not a miss. |
| **Session-reset abuse** ("new task" to wipe state) | Agent cannot reset state (D12.3). A new session is re-seeded from the principal's audit history (§3). |
| **Duplicate / idempotent steps** (repeated `add_payee`) | A repeated, successful add in `S3` re-binds `added_payee_id` to the latest canonical digest; a failed add does not alter state. No off-by-one advance. |
| **Cross-session smear** (chain split across two runs) | The `principal` anchor + audit replay reconstructs the prefix in the second session, so the terminal transfer still trips. |

---

## 8. DENY vs GATE — the emission rules

| Situation | Verdict | rule_id (example) | Rationale |
|---|---|---|---|
| Full kill chain: `S3` + `H(transfer_funds.to) = binding_digests["added_payee_id"]` | **DENY** | `seq.recon_add_drain.terminal` | High-confidence modeled fraud; hard-block without spending a human approval. |
| Near-miss at `S3`: target digest differs from `binding_digests["added_payee_id"]` | `None` from sequence; **GATE** from per-call policy | `gate.fund_transfer` (D5) | D16 avoids duplicate gate semantics. Preserve `S3`; ordinary fund-transfer approval decides execution. |
| No modeled chain at a blocking/escalating transition | `None` | — | Fall through to per-call policy (§2). |

Design stance: **the sequence engine only ever tightens.** It can turn a per-call `ALLOW`/`GATE`
into a `GATE`/`DENY`; it never loosens a per-call `DENY`. This preserves fail-closed and keeps the
independence claim clean — the automaton is a strictly additive containment layer.

---

## 9. How this maps to the policy schema (D2, proposal — needs sign-off)

Modeled chains are declared as **data**, not code, following D2's `trigger/check/enforce` structure.
Proposed `SequenceConfig` shape follows below. Under D17, `interface-contracts.md` treats the loaded
`Policy` as an opaque validated value; the existing Python skeleton is deferred to implementation.

```yaml
sequences:
  - name: recon_add_drain
    domain: banking
    steps:                       # ordered; each references a per-call trigger
      - trigger: get_balance
        to: S1_BALANCE
      - trigger: list_payees
        from: S1_BALANCE
        to: S2_PAYEES
      - trigger: add_payee
        from: S2_PAYEES
        to: S3_PAYEE_ADDED
        bind: {added_payee_id: "args.payee_id"}
      - trigger: transfer_funds
        from: S3_PAYEE_ADDED
        check:
          - predicate: target_is_bound_payee
            params: {argument: "to", binding: "added_payee_id"}
        enforce: DENY
        rule_id: seq.recon_add_drain.terminal
```

`check` entries reference **named, vetted predicate functions** (the immutable runtime registry in
`src/policy/predicates.py`), never inline code — policy stays inspectable data (D2). Sequence checks
receive monitor-owned `PredicateContext.binding_digests`; that context is not YAML and is not
agent-authored. The loader rejects an unregistered predicate (fail-closed at load time).
If the terminal predicate does not match, the sequence layer returns `None`; the canonical chain
does not declare a negated duplicate gate rule. D5's per-call fund-transfer rule supplies the
traceable `GATE` decision (D16).

> The concrete field names above are a **proposal**. Per the working agreement, the policy YAML
> schema is an "ask first" surface; this section is for review, not a committed schema.

---

## 10. Chain progress is first-class in the audit log (D12.4)

Every advance emits a `ChainProgressEvent` (subject key, chain name, from-node, to-node, **mapping
of binding name to canonical digest**, timestamp), and every blocking/escalating verdict emits a
`DecisionEvent` with the chain-scoped `rule_id`. A single hash of the entire bindings object would
be non-reconstructible and is therefore explicitly rejected. Replay rebuilds the node and named
digests, not merely the decisions. Eviction and idle-expiry are their own events
(`EvictionEvent`, `SessionLifecycleEvent`) so state clearing is never silent.

When a subject exceeds its chain cap, advancement rank is the declared step index in `ChainSpec`.
Eviction orders by lowest rank, then oldest `updated_at`, then chain name for a deterministic tie.
Each removed chain produces its own `EvictionEvent` before the in-memory entry is discarded.

---

## 11. Known limitations (carried into `residual-risks.md`)

- **Bounded recognition.** Only pre-modeled chains are caught (Schneider 2000). A novel ordering the
  automaton has not been taught passes the sequence layer and is judged only per-call.
- **Pacing vs lookback.** A chain paced slower than the 24 h lookback loses its prefix on replay.
- **Eviction pressure.** An attacker controlling many principals can force least-advanced-first
  eviction of a real chain's progress.

Each is documented with its design consequence in `residual-risks.md`.
