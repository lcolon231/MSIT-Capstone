# Architecture — Module Responsibilities and Boundaries

> **Phase 2 design, v2.2 (2026-08-24).** Design-only. This document fixes the module boundaries
> and the dependency rules that the Phase 2 build must not violate. It is authoritative over
> ad-hoc import decisions made during implementation. Companion documents:
> `sequence-engine.md` (the D1 automaton), `interface-contracts.md` (the normative non-executable
> interfaces), and `residual-risks.md`.
> The Python skeleton is not modified by this documentation pass; under D17 it is deferred to
> implementation, and §7 records where it differs from the confirmed design.
>
> Governing decisions: **D1** (explicit kill-chain automaton), **D2** (declarative YAML policy),
> **D5** (four gate classes), **D6** (deterministic scoring), **D8** (DENY + GATE only),
> **D9** (trusted operator; external indirect-injection adversary),
> **D11** (process boundary; monitor owns tools; agent proposes), **D12** (sequence-state
> retention via audit replay), **D13** (ATLAS-primary scenario labels), **D14** (trusted
> launcher-bound sessions), **D15** (live-state clearing preserves replay history), and **D16**
> (canonical near misses fall through to D5), and **D17** (documentation-only interface contract).

---

## 1. The one non-negotiable invariant

**The verdict is a pure function of `(call, policy, sequence_state)`.** Nothing the agent emits —
not its reasoning, not an argument named `approved`, not a persuasive `reason` string, not a
tool name it invents — can influence the verdict except as fields of *the call being judged*. Every
module boundary below exists to make that invariant structurally true rather than merely
promised.

Corollaries enforced by the layering:

- **Trust boundary.** The Provider operator and console are trusted; a malicious/compromised
  operator is out of scope. The LLM agent is outside the trust boundary because external parties
  can poison ingested content and tool results. Controls below constrain proposals from that
  agent; they do not invent operator-adversary controls contrary to D9.
- **No LLM in the enforcement or scoring path.** The only LLM (`src/agent/model.py`) lives on the
  far side of the transport boundary and can never be imported by the monitor.
- **Fail-closed everywhere.** The absence of a matching rule, a malformed proposal, an unknown
  tool, a missing approval, or a failed policy load all resolve to `DENY` — never an exception
  that crashes open, never a passthrough.
- **Complete mediation.** No tool executes without a `Decision`. The only code path to a tool is
  through `MonitorService`, and the agent has no import path to `src/tools`.
- **Tool results remain untrusted.** A result may contain a mid-task indirect injection and may
  induce the next proposal. It cannot change the completed verdict, and the induced proposal must
  traverse the same mediation path again.

---

## 2. Layer map (dependency direction points downward)

```
                    src/agent           ← proposes calls; holds the LLM; TRUSTS NOTHING below it
                        │  (imports only ▼)
                src/transport/contract   ← neutral DTOs (ToolCallProposal, ToolResult, Verdict)
                src/transport/client     ← agent capability: dispatch(envelope), no session API
        ┌───────────────┴───────────────┐  the boundary (in-process seam OR loopback socket)
        ▼                               ▼
 src/transport/inprocess         src/transport/loopback (client; enforcement-free)
        │                               │ loopback socket
        │                               ▼
        │                    src/transport/loopback_server
        └───────────────┬───────────────┘
                        ▼
                 src/monitor/service      ← composition root of the enforcement side
              ┌─────────┼──────────┬─────────────┐
              ▼         ▼          ▼             ▼
      src/monitor/  src/policy  src/audit    src/tools
      {verdict,     (loader,    (writer,     (mock tools over
       sequence,     schema,     replay,      in-process state)
       gate,         predicates) events)
       session,
       types}
```

`src/transport/contract.py` is a **pure stdlib leaf**. `src/monitor/types.py` imports only stdlib
plus that neutral contract and is otherwise a leaf imported widely. These are the only shared
vocabulary modules; everything else depends in one direction.

---

## 3. Module responsibilities and import rules

For each module: **Owns** (its responsibility and state), **May import**, **Must never import**.
"Must never import" violations are the ones the import-graph test (`tests/test_import_graph.py`)
turns into failing builds.

### 3.1 `src/transport/contract.py` — the neutral vocabulary
- **Owns:** the DTOs that cross the boundary in both directions: `ToolCallProposal` (what the
  agent emits — tool name + JSON args, **nothing else**), `MalformedProposal` (JSON-decodable model
  output that failed proposal parsing but must still be mediated), their `ProposalEnvelope` union,
  `ToolResult` (status + untrusted JSON payload + a redacted decision summary), `SessionHandle`
  (opaque and monitor-issued, used only by trusted bootstrap/concrete transports), and `Verdict`.
  Pure data; no behaviour beyond construction/serialization signatures.
- **May import:** stdlib only.
- **Must never import:** anything else under `src/`. This is what lets the agent share a
  vocabulary with the monitor without ever reaching `tools` or `policy`.

### 3.2 `src/transport/client.py` — the boundary contract
- **Owns:** the agent-facing `Transport` protocol:
  `dispatch(proposal: ProposalEnvelope) -> ToolResult`. Abstract only. Session lifecycle is
  deliberately absent: the trusted launcher obtains a monitor-issued, high-entropy capability,
  constructs a session-bound concrete transport, and injects that transport before the agent loop
  starts. The concrete transport attaches the capability as transport metadata; it is never model
  context or proposal data. Nothing the agent can call creates, chooses, or rotates a session
  (D12.2/D12.3/D14).
- **May import:** `src/transport/contract`, stdlib.
- **Must never import:** any concrete transport (`inprocess`, `loopback`), `monitor`, `policy`,
  `tools`. Keeping the protocol module implementation-free is what keeps the agent's transitive
  import closure clean.

### 3.3 `src/transport/inprocess.py` and `src/transport/loopback.py` — the two implementations (D11)
- **Owns:** the two `Transport` implementations behind one interface. `InProcessTransport` calls
  `MonitorService.handle(...)` directly with a bootstrap-bound session (same address space — the
  documented **scope cut**). `LoopbackTransport` holds a bootstrap-bound session, serializes only
  the proposal plus its private capability as transport metadata, POSTs to loopback, and
  deserializes `ToolResult`. The agent-facing method has no session parameter.
  Loopback is the **D11 primary path**.
- **May import (`inprocess.py`):** contract/client, `src/monitor/service`, stdlib.
- **May import (`loopback.py`):** contract/client and stdlib HTTP/JSON **only**. It must remain safe
  to load in the agent process. No new third-party dependency is introduced.
- **Must never import:** `src/agent`. The transport is wired to the agent by the composition root
  via dependency injection; the agent never names a concrete transport.

### 3.3a `src/transport/loopback_server.py` — monitor-side HTTP adapter
- **Owns:** loopback-only request decoding, the launcher-only bootstrap endpoint (session
  creation gated by a high-entropy capability), session validation, and delegation to
  `MonitorService.handle`. The server passes decoded objects — including malformed shapes — to the
  service's normalization boundary; it never bypasses the service or crashes open. A missing/invalid
  bootstrap capability is refused (no session, so nothing can dispatch); a bad body or unknown
  session flows into the service's fail-closed path and returns a DENY `ToolResult`, never an
  HTTP-path exception that could bypass mediation.
- **May import:** `src/monitor/service`, `src/transport/contract`, `src/transport/loopback` (for the
  shared bootstrap-header name), stdlib HTTP/JSON.
- **Must never import:** `src/agent`; it runs only in the monitor process.

**Status: implemented (issue #54).** The client/server split above is in place — `loopback.py`
holds the client half (contract + stdlib http/json only; `tests/test_import_graph.py` asserts its
closure never reaches `monitor`/`tools`/`policy`) and `loopback_server.py` holds the
`MonitorService`-importing half. `src/monitor_server.py` runs the server as its own process; the
trusted launcher (`--transport loopback`) spawns it, mints the bootstrap capability, and speaks
HTTP to it. `tests/test_loopback_transport.py` proves the full kill chain is blocked with agent and
monitor in **separate OS processes**, and `src/eval/loopback_parity.py` shows every suite scenario
yields the same decision stream and outcome over loopback as in-process.

### 3.4 `src/monitor/types.py` — core enforcement value types
- **Owns:** `Verdict` (re-exported/aligned with contract), `Decision` (frozen; **always** a
  non-null/non-optional `RuleId`), `ToolCall` (the **monitor-enriched** call: normalized proposal +
  monitor-assigned `session_id`, monitor-resolved `resource_principal`, validation status, call id,
  timestamp), `Principal`, `SubjectKey` (`(session_id, principal)`), `SessionId`, `GateClass`, and
  `SequenceState`. Invalid calls may carry no resolved principal, but can still be evaluated and
  denied; only valid/resolved calls may enter sequence state or dispatch.
- **May import:** `src/transport/contract` (to build `ToolCall` from `ToolCallProposal`), stdlib.
- **Must never import:** `policy`, `sequence`, `gate`, `service`, `audit`, `tools`, `agent`. It is a
  leaf; keeping it a leaf prevents import cycles and lets `policy` depend on it safely.

### 3.5 `src/monitor/verdict.py` — the pure verdict engine
- **Owns:** `evaluate(call, policy, state) -> Decision`. The fail-closed order from
  `tasks/spec.md` §9:
  monitor-assigned structural validation first; sequence engine; per-call rule match; default
  `DENY`. Pure — no I/O, no mutation, no clock, no randomness. Unknown/malformed calls receive
  system-scoped rule ids rather than throwing.
- **May import:** `src/monitor/types`, `src/monitor/sequence`, `src/policy` (to read `Policy`/
  `Rule` and run named predicates).
- **Must never import:** `audit`, `service`, `gate` (verdict does not write logs, does not manage
  queues), `tools`, `agent`, any transport. Side effects belong to the service layer.

### 3.6 `src/monitor/sequence.py` — the kill-chain automaton (D1)
- **Owns:** the deterministic automaton: `classify(call, state, policy) -> Decision | None`
  (pure; returns `DENY`/`GATE` when a modeled chain reaches a blocking transition, else `None`)
  and `advance(call, policy, state) -> SequenceState` (pure; returns the next state after a
  *permitted, successfully executed* call). `policy` is explicit because it owns the modeled
  transition table. Full design in `sequence-engine.md`.
- **May import:** `src/monitor/types`, `src/policy` (to read `ChainSpec`s).
- **Must never import:** `audit`, `service`, `gate`, `tools`, `agent`, transport. State is passed
  in and returned out; it is never read from or written to storage here.

### 3.7 `src/monitor/gate.py` — the approval gate (D5)
- **Owns:** `GateClass` classification (`file delete · network send · data export · credential
  access`), the `PendingApproval` value type, and the `ApprovalQueue` (process-owned, mutable):
  enqueue on `GATE`, list pending, resolve by monitor-issued approval id. **Fail-closed:**
  unresolved/timeout prevents execution and produces `ResultStatus.DENIED`, while the original
  pure verdict remains `GATE`. The queue accepts operator decisions *only* by approval id from the
  console; it never reads `approved`/`reason` from the call's arguments.
- **May import:** `src/monitor/types`, stdlib.
- **Must never import:** `agent`, transport, `tools`. It must have no channel through which agent
  text can resolve an approval. Gate classification may inspect the validated `ToolCall`; queue
  resolution accepts only a monitor-issued approval id and trusted operator action, never call
  arguments such as `approved` or `reason`.

### 3.8 `src/monitor/session.py` — session identity and retention (D12)
- **Owns:** monitor-assigned internal `SessionId`, opaque-handle minting/validation for trusted
  bootstrap (the agent cannot supply, choose, or rotate it),
  idle-expiry (default 30 min, configurable, logged when it fires), and per-subject chain caps
  with **least-advanced-first eviction, every eviction logged as its own audit event**. Holds the
  live in-memory `SequenceState` per `SubjectKey` and seeds a new session for a principal by
  asking `audit.replay` to reconstruct progress over the lookback window (default 24 h). Replay
  folds recent events by principal, restores named binding digests, then re-keys the snapshot to
  the new monitor-assigned session. Under D15, session end and idle expiry invalidate the
  capability and clear this **live entry**, but do not erase within-lookback principal history or
  act as replay barriers. The D12 cap is per subject and does not bound total subject cardinality;
  that availability exposure is explicit in `residual-risks.md` R3.
- **May import:** `src/monitor/types`, `src/audit` (replay + write lifecycle/eviction events).
  It may also import the neutral transport contract for opaque `SessionHandle` validation.
- **Must never import:** `agent`, concrete transport implementations, `tools`, or policy internals
  beyond retention config.

### 3.9 `src/monitor/service.py` — the enforcement composition root
- **Owns:** `MonitorService.handle(payload: object, session: SessionHandle | None) -> ToolResult` —
  the decision-and-dispatch endpoint (D11). Orchestrates the full single-call flow: validate the
  handle; normalize even malformed decoded input into a call; resolve
  the principal through the selected tool's schema; enrich it into `ToolCall`; call `evaluate`;
  write the decision; on `GATE`, enqueue and audit the operator resolution; on `ALLOW` (or approved
  `GATE`), dispatch via the registry and audit the hashed tool outcome; after a **successful** tool outcome, call
  `advance(call, policy, state)`, commit state, and write chain-progress events; then wrap the raw
  outcome as `ToolResult`. This is the *only* place tools are executed.
  A gate denial/timeout does not mutate the pure `Decision` from GATE to DENY: the dispatch status
  is `DENIED`, and `ApprovalResolutionEvent` records the operator outcome. This keeps `evaluate`
  pure while implementing D5's "no approval means no execution" rule.
  For the canonical sequence, only an export to the bound new destination produces a sequence `DENY`;
  a different target makes sequence classification return `None`, preserves `S3`, and falls
  through to the ordinary D5 data-export `GATE` (D16).
- **May import:** everything on the enforcement side — `monitor/*`, `policy`, `audit`, `tools`,
  `transport/contract`.
- **Must never import:** `src/agent`. The dependency points from agent → transport → service, never
  back.

### 3.10 `src/policy/` — declarative policy (D2)
- **Owns:** the YAML schema types (`Policy`, `Rule`, `Trigger`, `Check`,
  `SequenceConfig`, `ChainSpec`), the loader (rejects unknown fields and malformed policy with
  clear errors — **fail-closed: a load failure yields an all-DENY policy, never an empty allow**),
  and the **named predicate registry** (`predicates.py` — vetted pure functions referenced by name
  from YAML; policy stays *data*, never code, per D2). The loaded runtime `Policy` carries an
  immutable trusted registry so `evaluate(call, policy, state)` has no hidden mutable input; the
  registry is not serialized to YAML and does not change the proposed YAML schema.
- **Argument-normalization contract:** allow rules operate only on canonical values and use full
  matches, never substring matches. Command canonicalization recognizes `${IFS}` splitting and
  bounded base64-wrapped payloads; ambiguous encodings fail the predicate. Text normalization
  rejects mixed-script Unicode look-alikes rather than guessing. Paths normalize separators and
  dot segments, then require containment under the mock root (traversal/absolute escape/symlink
  ambiguity fails closed). Domains are case/IDNA normalized and compared for exact equality, so
  `attacker@example.com.evil.com` cannot satisfy an `example.com` rule. Predicate errors are a
  failed match; if no safer rule applies, `evaluate` returns the default DENY.
- **May import:** `src/monitor/types` (predicates operate on `ToolCall`), the neutral
  `src/transport/contract` for `Verdict`, stdlib, `yaml`.
- **Must never import:** `monitor/verdict`, `sequence`, `gate`, `service`, `audit`, `tools`,
  `agent`, or concrete transport implementations. Policy is inert data + pure predicates; it
  evaluates nothing on its own.

### 3.11 `src/audit/` — append-only JSONL + replay (D12, criterion #8)
- **Owns:** the append-only JSONL `AuditWriter`; the event types (`DecisionEvent`,
  `ChainProgressEvent`, `EvictionEvent`, `SessionLifecycleEvent`, `ApprovalResolutionEvent`,
  `ToolExecutionEvent`);
  `replay(...)`; and `reconstruct_sequence_state(path, target, now, lookback) -> SequenceState`
  (D12.4 — replay reconstructs *sequence state*, not only decisions). `ChainProgressEvent` records a mapping of
  binding name to canonical SHA-256 digest — not one opaque hash of the entire binding map — so
  replay can restore the names and compare a later argument's digest without recovering plaintext.
  Also owns `hash_arguments(args) -> str`: **arguments are hashed, never logged in plaintext.**
  These hashes support deterministic comparison and reduce plaintext exposure; they are not
  encryption and do not make the file tamper-evident. Hash chaining/signatures remain future
  hardening rather than an implied property of JSONL append mode.
- **May import:** `src/monitor/types`, the neutral contract for `Verdict`, stdlib (`json`,
  `hashlib`).
- **Must never import:** `policy`, `verdict`, `sequence`, `gate`, `service`, `tools`, `agent`,
  or concrete transport implementations. The audit log is a sink and a source of truth; it does
  not make decisions.

### 3.12 `src/tools/` — mock tools over in-process state
- **Owns:** the inert `ToolMetadata` schema (`name`, allowed arguments, principal argument), the
  `Tool` protocol (`name` and `execute(args) -> ToolExecution`), the raw `ToolExecution` value,
  and the `ToolRegistry` (owned
  and invoked *only* by `MonitorService`), and the mock domains (RMM first: `list_endpoints`,
  `list_shares`, `register_destination`, `export_records` over an in-process `EndpointState`; files/network/
  creds later). **No real egress, no real filesystem** — all state is in-process.
- **May import:** `src/monitor/types` (resolved `Principal`), the neutral transport contract
  (`JsonValue` only), and stdlib.
- **Must never import:** `agent`, transport, `policy`, `verdict`, `sequence`, `gate`. A tool never
  constructs a `ToolResult` or decides whether it may run; it is only reached after a `Decision`.
  Before verdict, the service may ask the registry to validate/resolve against `ToolMetadata`; it
  never calls a method on the tool implementation.

### 3.13 `src/agent/` — the agent loop and the model (D4)
- **Owns:** the agent loop (`loop.py`) and the pluggable model client (`model.py`: `ModelClient`
  protocol, `OllamaModel`, `StubModel` for CI). The loop turns a task into `ToolCallProposal`s,
  dispatches them over the injected, session-bound `Transport`, feeds untrusted `ToolResult`s back
  to the model, and repeats. A poisoned result is therefore a first-class D9 input to the next
  turn, whose next proposal is mediated again.
- **May import:** `src/transport/contract`, `src/transport/client`. **That is the entire allowed
  set.**
- **Must never import:** `src/tools`, `src/policy`, `src/monitor`, or any concrete transport. This
  is the tamper-resistance boundary and the subject of the import-graph assertion. The agent
  cannot obtain a tool implementation or policy object; it can only propose a tool-name string and
  arguments over the contract.

### 3.14 `src/web/` — operator console (out of scope for this design pass)
Named here for completeness (Phase 4). It reads the audit log and the `ApprovalQueue`; it may
import `audit` and `monitor/gate`+`session` read interfaces, never `agent` or `tools`. Detailed
design deferred.

### 3.15 `src/eval/` — red-team scenarios, deterministic scoring, metrics (Phase 5)
Out of scope for this design pass except for the **scenario schema**, which D13 fixes now.
- **Owns:** the scenario schema (`scenario.py` — D13: `atlas_technique` primary/required,
  `agent_safetybench_mode` optional secondary; plus a deterministic `PostConditionChecker`, D6),
  and later the runner and metrics.
- **May import:** `src/audit` (to inspect a recorded run), `src/monitor/types`, and the transport
  contract to drive an agent run through the mediated path.
- **Must never import:** `eval` must never be imported by the enforcement path, and **no LLM** may
  appear in a scoring metric (D6, `tasks/spec.md` §10). Eval observes; it never decides a verdict.

---

## 4. The tamper-resistance boundary (D11) and its test

The agent runs as its own process (loopback) or, as a documented scope cut, in-process behind the
same `Transport` interface. Under **both** forms, `src/agent` has no import path to `src/tools` or
`src/policy`. The evidence is `tests/test_import_graph.py` (a **real, runnable deliverable**, not a
stub): it parses the AST of every module under `src/agent/**`, computes the transitive import
closure restricted to first-party `src.*` modules, and asserts the closure contains **no**
`src.tools`, `src.policy`, or `src.monitor` module.

Why this holds structurally:

- The agent imports only `transport.contract` (pure leaf) and `transport.client` (protocol,
  implementation-free). Neither reaches `tools`/`policy`/`monitor`.
- `transport.loopback` (the client half) is enforcement-free and its server adapter
  (`loopback_server.py`) is a separate module that runs in the monitor process. Beyond the required
  agent-closure test, `tests/test_import_graph.py` now also asserts the loopback **client** closure
  never reaches `monitor`/`tools`/`policy`, so the split is self-enforcing. `transport.inprocess`
  does reach the monitor, explicitly as the weaker scope cut.
- Under **loopback**, tool and policy objects exist only in the monitor process; the client import
  closure cannot load them. The OS boundary prevents object/memory access, while deployment should
  package the agent-side entry point with only agent and client-transport modules. The threat model
  excludes code modification or arbitrary code execution in the agent process (D9).
- Under **in-process**, isolation is *source-level* (the seam) but not address-space level. This is
  weaker and is exactly why loopback is the D11 primary; see `residual-risks.md`.

---

## 5. Two DTOs, deliberately distinct

- `ProposalEnvelope` (contract) — **agent-side input**: either `ToolCallProposal(tool, args)` or a
  JSON-decodable `MalformedProposal`. Neither carries session id nor an authoritative principal.
  Arguments may name a target resource, but the monitor validates and canonicalizes that target
  before assigning `ToolCall.principal`. Malformed content is hashed/audited and receives a
  system-scoped DENY; it never disappears as a client-side exception.
- `ToolCall` (monitor/types) — **monitor-enriched**: normalized proposal plus monitor-assigned
  `session_id`, schema-resolved `resource_principal`, structural validation status, call id, and
  timestamp. Principal resolution may inspect validated call arguments, but the agent cannot
  directly assert the resolved identity; ambiguous/malformed identity is marked unresolved and
  denied before sequence matching.

`evaluate` and every predicate operate on `ToolCall`. The agent never constructs one. This split is
the structural form of "agent output never controls a verdict": the proposed name/arguments are
treated as untrusted input, while session, validated identity, status, call id, and time are assigned
on the enforcement side. Session creation is not an agent capability.

The session capability is deliberately absent from both DTOs. It is a private property of the
session-bound concrete transport, attached outside the proposal and validated before enrichment
(D14). Consequently, a model-generated field named `session`, `approved`, or similar remains an
ordinary untrusted argument and cannot alter identity or approval state.

---

## 6. What each "Ask first" boundary touches here

Per `tasks/spec.md` §10 and the working agreement, the following are *not* changed in this design pass and
require sign-off before Phase 2 implements them:

- **Policy YAML schema.** Section 3.10 and `sequence-engine.md` propose the schema shape (following
  D2's `trigger/check/enforce` structure); no `policies/*.yaml` exists yet, so this is a *proposal
  to review*, not a change to an existing schema.
- **New dependencies.** None introduced. Loopback uses stdlib only.
- **Metric definitions.** Untouched (owned by `src/eval`, Phase 5).

---

## 7. Implementation handoff — source deviations from the normative interface contract

`interface-contracts.md` is authoritative for the target interface shape under D17. The table below
records current source deviations for the later implementation phase; it is not implementation
performed in this pass.

| Existing skeleton location | Why it remains partial against this design |
|---|---|
| `src/transport/client.py` | The agent-facing protocol still exposes `open_session` and accepts a session handle on `dispatch`; D14 requires trusted-launcher creation and a session-bound, dispatch-only agent capability. |
| `src/transport/loopback.py` | Client and server share one module, so importing the client imports `MonitorService`; §3.3a requires a physical client/server split for the primary loopback path. |
| `src/transport/contract.py` + `src/monitor/types.py` | The types do not yet give malformed/unknown/unresolved proposals a representable monitor-side form, although complete mediation requires those inputs to produce a `Decision`. |
| `src/audit/events.py` | `ChainProgressEvent` stores one opaque binding-map hash. Replay needs named binding digests so it can reconstruct and compare bindings without plaintext. |
| `src/monitor/sequence.py` | `advance` does not receive `Policy`, even though the policy owns the modeled transition table; its near-miss docstring also still describes a sequence `GATE`, now stale under D16. |
| `src/tools/` | Tool implementations currently construct transport `ToolResult`s; the target boundary has tools return raw mock outcomes and lets the monitor construct the agent-visible result. |
| `tests/test_import_graph.py` | The required agent-closure assertion exists and is complete. A loopback-client closure assertion would strengthen packaging evidence, but is not substituted for the required agent test. |

No Python change is authorized by this section. It is the implementation-session checklist after
the design is approved.
