# Interface Contracts — Normative Design-Only Target

> **Phase 2 design, v1 (2026-08-24).** This is a non-executable contract document, confirmed by
> D17. It replaces the original `src/` interface-skeleton deliverable for design review. The
> existing Python skeleton is deferred to implementation and is not authoritative where it differs
> from this document.
>
> This document does **not** change the policy YAML schema, add a dependency, define a metric, or
> provide functional code. Python-like notation below expresses type and operation contracts only.

---

## 1. Contract-wide invariants

Every implementation of these interfaces must preserve all of the following:

1. **Pure verdict.** The normative verdict operation is exactly
   `evaluate(call: ToolCall, policy: Policy, state: SequenceState) -> Decision`. It performs no
   I/O, mutation, clock reads, randomness, tool execution, approval lookup, or audit write.
2. **Fail closed.** No matching rule means `DENY`. Malformed input, unknown tools, invalid session
   capabilities, unresolved principals, invalid arguments, predicate failures, and policy-load
   failures never become `ALLOW`.
3. **Complete mediation.** The agent proposes; the monitor decides and dispatches. No tool is
   reachable from the agent process, and no external proposal bypasses normalization and verdict.
4. **Agent output is untrusted data.** Tool name and arguments may be inspected as the proposed call
   being judged. Agent reasoning, final text, and persuasive fields such as `approved`, `reason`, or
   `session` have no privileged meaning and cannot resolve identity or approval.
5. **No LLM in enforcement or scoring.** Policy and predicates are deterministic. Scenario scoring
   is a deterministic post-condition check.
6. **Every `Decision` is traceable.** `Decision` is immutable and always has a non-empty,
   non-optional `rule_id`, including system denials.
7. **Audit before effect.** A `DecisionEvent` must be durably appended before any permitted tool
   executes. If the audit sink cannot accept the record, dispatch fails closed and the tool does
   not run.
8. **Arguments remain private.** Audit records store canonical SHA-256 digests, never plaintext
   arguments. Named sequence bindings are stored as a name-to-digest mapping so replay is possible.
9. **Boundary validation is centralized.** Transport decoding and monitor normalization validate
   external shapes. Pure internal functions receive typed values and do not duplicate boundary
   parsing.

---

## 2. Trust domains and dependency direction

| Domain | Holds | May communicate with |
|---|---|---|
| Agent process — untrusted | Model, agent loop, session-bound transport client | Neutral transport contract and loopback monitor endpoint only |
| Trusted launcher/control plane | Session bootstrap authority and concrete transport construction | Monitor session control and agent process startup |
| Monitor process — trusted | Policy, predicates, sequence state, approvals, audit writer, tool registry, tool implementations | Agent only through transport DTOs; operator through approval control |
| Operator console — trusted | Human approval decisions | Approval queue by monitor-issued approval identifier |

Dependency direction is agent → neutral transport → monitor service → policy/state/audit/tools.
Nothing on the enforcement side imports the agent. `src/agent` has no direct or transitive import
path to `src/tools`, `src/policy`, or `src/monitor`; the existing import-graph assertion is the D11
evidence.

---

## 3. Value-type contracts

All value types below are immutable unless the table explicitly identifies an owned mutable
service. Identifier types are distinct logical types even when serialized as strings.

| Type | Required shape and invariants | Owner |
|---|---|---|
| `JsonValue` | Recursive JSON value: null, boolean, number, string, array, or string-keyed object. No arbitrary Python objects cross transport. | Transport contract |
| `ToolCallProposal` | `tool: str`, `args: Mapping[str, JsonValue]`. Contains no session, principal, approval, verdict, reasoning, or timestamp field. | Transport contract |
| `MalformedProposal` | Represents bytes/JSON that cannot become a valid proposal. Carries a monitor-safe validation code and a digest of the received material, not trusted fields extracted from it. | Transport boundary |
| `ProposalEnvelope` | Discriminated union of `ToolCallProposal` and `MalformedProposal`; every decoded request becomes one variant. | Transport contract |
| `SessionCapability` | Opaque, high-entropy monitor-issued capability privately held by a concrete transport. Never model-visible and never part of `ProposalEnvelope` or `ToolCall.args`. | Trusted launcher + monitor |
| `SessionId` | Internal monitor identity resolved from a valid capability. The agent cannot construct, choose, or rotate it. | Session registry |
| `Principal` | Canonical account, endpoint, or client the call acts against, resolved by trusted tool metadata/schema. Agent arguments may identify a candidate but are not authoritative. | Monitor normalization |
| `SubjectKey` | Composite `(SessionId, Principal)` used for live sequence state. | Session registry |
| `CallValidation` | One of `VALID`, `MALFORMED`, `UNKNOWN_TOOL`, `INVALID_SESSION`, `UNRESOLVED_PRINCIPAL`, or `INVALID_ARGUMENTS`. Every non-`VALID` value maps deterministically to a system `DENY`. | Monitor normalization |
| `ToolCall` | Normalized tool name and canonical arguments plus monitor-owned `SessionId`, resolved `Principal` when available, `CallId`, monitor timestamp, and `CallValidation`. The agent never constructs it. | Monitor types |
| `Verdict` | Exactly `ALLOW`, `DENY`, or `GATE`. | Neutral contract |
| `Decision` | Frozen value containing `verdict`, non-empty `rule_id`, operator-readable `reason`, and optional `gate_class` only when verdict is `GATE`. | Verdict engine |
| `GateClass` | Exactly file delete, network send, data export, or credential access (D5). | Approval gate |
| `DecisionSummary` | Agent-visible subset of a decision: verdict, rule id, and bounded explanation. It exposes no policy internals or approval authority. | Transport contract |
| `ResultStatus` | `EXECUTED`, `TOOL_FAILED`, or `DENIED`. A synchronous dispatch waits for gate resolution up to the configured timeout; pending approval remains monitor-internal. | Transport contract |
| `ToolResult` | `status`, `DecisionSummary`, and untrusted JSON payload only when a tool ran. A denied/timeout gate retains the original `GATE` decision summary while status is `DENIED`. | Monitor service |
| `ChainProgress` | Chain name, current node, named canonical binding digests, per-step timestamps, and `updated_at`. Contains no plaintext bound arguments. | Sequence engine |
| `SequenceState` | Immutable mapping from `SubjectKey` to bounded chain progress. Pure operations return a new value. | Session registry |
| `Policy` | Immutable, successfully validated policy value consumed by pure verdict/sequence operations. YAML field names remain subject to the separate schema sign-off noted in `sequence-engine.md` §9. | Policy loader |

### Decision construction rules

| Condition | Required verdict | Required rule-id family |
|---|---|---|
| Invalid or expired session capability | `DENY` | `system.invalid_session` |
| Malformed proposal or arguments | `DENY` | `system.malformed_call` |
| Unknown tool | `DENY` | `system.unknown_tool` |
| Principal cannot be resolved unambiguously | `DENY` | `system.unresolved_principal` |
| Full canonical recon-register-exfil terminal match | `DENY` | `seq.recon_register_exfil.terminal` |
| Canonical `S3` export target does not match | Sequence returns no decision; per-call policy returns `GATE` | `gate.data_export` |
| Matching per-call rule | Rule's `ALLOW`, `DENY`, or `GATE` | Human-authored rule id |
| No matching rule | `DENY` | `system.default_deny` |

---

## 4. Operation contracts

The signatures below are descriptive contracts, not executable definitions.

### 4.1 Agent-facing transport

| Operation | Contract |
|---|---|
| `Transport.dispatch(proposal: ProposalEnvelope) -> ToolResult` | The agent's only capability. The concrete transport adds its private session capability outside the proposal. There is no session-creation method and no session argument. |
| `InProcessTransport.dispatch(...)` | Calls the same monitor service contract in one address space. Documented weaker scope cut; never imported by `src/agent`. |
| `LoopbackTransport.dispatch(...)` | Serializes the envelope as JSON, attaches the private capability as transport metadata, sends only to loopback, validates the response shape, and returns `ToolResult`. Imports no monitor, policy, or tool module. Primary D11 path. |

Transport/network failure is not an implicit allow. A semantic rejection returned by the monitor
is a denied `ToolResult`; a connection failure never invokes a local tool or manufactures an
`ALLOW` response.

**Retry contract:** Phase 2 dispatch is explicitly **unsafe to retry automatically**. The loopback
client performs no transparent retry of a timed-out state-changing request because the tool may
have executed before the response was lost. A timeout aborts the agent task as outcome-unknown; it
never causes a second dispatch. Production retry support would require a transport-generated
idempotency key, an atomic intent claim, request-body digest checking, and durable outcome
reconciliation. That mechanism is outside the mock-tool capstone scope rather than silently
promised by this interface.

### 4.2 Trusted session control

| Operation | Contract |
|---|---|
| `SessionControl.open_session() -> SessionBinding` | Launcher-only. Mints internal `SessionId` plus an opaque capability and emits a session-open audit event. Not present on the agent-facing `Transport`. |
| `SessionControl.end_session(binding) -> None` | Launcher/operator control only. Invalidates the capability, removes live state, and emits a session-end event. It does not erase within-lookback principal history (D15). |
| `SessionRegistry.expire_idle(now) -> expired subjects` | Monitor-owned sweep. Invalidates capabilities and removes live entries idle beyond the configured default of 30 minutes; emits one lifecycle event per expiry. |
| `SessionRegistry.state_for(session, principal) -> SequenceState` | Returns live state or seeds it by replaying within-lookback events for the principal and re-keying them to the new session. |
| `SessionRegistry.commit(subject, next_state) -> None` | Stores post-execution state, enforces the per-subject chain cap, evicts least-advanced-first, and writes one event per eviction. |

### 4.3 Monitor decision and dispatch

| Operation | Contract |
|---|---|
| `MonitorService.handle(payload, capability) -> ToolResult` | Sole decision-and-dispatch entry point. It validates capability and payload, normalizes to `ToolCall`, reads state, evaluates, writes audit, gates/executes if permitted, advances only after successful execution, and returns the result. |
| `normalize(payload, capability, tool_metadata, now) -> ToolCall` | Boundary operation. Every input, including malformed and unknown calls, becomes a typed call with a validation status; it never executes a tool. |
| `evaluate(call: ToolCall, policy: Policy, state: SequenceState) -> Decision` | Pure and fail-closed. Order: validation denial → sequence classification → per-call rule → default denial. Exact normative verdict signature. |

The service must not catch an exception and continue to a tool. Any validation, policy, predicate,
gate, audit, registry, or execution-path uncertainty prevents execution.

### 4.4 Sequence engine

| Operation | Contract |
|---|---|
| `classify(call, state, policy) -> Decision or None` | Pure and read-only. Returns a sequence decision only when a configured blocking/escalating transition matches. For the canonical `S3` target mismatch, returns `None` under D16. |
| `advance(call, policy, state) -> SequenceState` | Pure. Called only after a permitted tool call succeeds. Applies configured transitions, preserves unmatched state, and returns a new snapshot. |
| `subject_of(call) -> SubjectKey or None` | Pure. Returns no subject for invalid/unresolved calls; those calls cannot enter sequence state. |

Canonical behavior is defined in `sequence-engine.md`; this document does not duplicate the policy
YAML field proposal.

### 4.5 Policy loading and predicates

| Operation | Contract |
|---|---|
| `load_policy(source) -> Policy` | Parses human-authored YAML, rejects malformed input, unknown fields, and unregistered predicate names. The composition root substitutes an immutable deny-all policy on any load failure. |
| `Policy.match(call, context) -> Rule or None` | Pure, deterministic first-match operation over validated rules. No rule means no allow. |
| `Predicate(call, params, context) -> bool` | Pure vetted function selected by registered name. Exceptions or ambiguity count as a failed match. Context is monitor-owned, never YAML- or agent-authored. |

Argument predicates canonicalize before matching and use anchored/full equality. They must fail
closed on `${IFS}` splitting, bounded base64 wrappers, mixed-script Unicode look-alikes, traversal
or absolute-path escape, symlink ambiguity, and exact-domain look-alikes such as
`attacker@example.com.evil.com`.

### 4.6 Approval gate

| Operation | Contract |
|---|---|
| `ApprovalQueue.enqueue(call, decision) -> PendingApproval` | Accepts only a monitor-produced `GATE` decision and creates a monitor-issued approval id. |
| `ApprovalQueue.list_pending() -> pending approvals` | Trusted console read operation. Returns monitor-owned approval records, never agent-authored approval claims. |
| `ApprovalQueue.resolve(approval_id, operator_action) -> ApprovalResolution` | Trusted console only. Agent arguments and output cannot call or influence it. |
| `ApprovalQueue.await_resolution(approval_id, timeout) -> ApprovalResolution` | Bounded synchronous wait. Denial or timeout prevents execution and produces `ResultStatus.DENIED`; approval permits the service to continue to dispatch. |

The original pure `Decision` remains `GATE`; approval resolution controls execution status and is
audited separately.

### 4.7 Audit and replay

| Operation | Contract |
|---|---|
| `AuditWriter.append(event) -> None` | Appends exactly one JSON object plus newline; never rewrites or truncates. Completion is required before dependent execution proceeds. |
| `hash_arguments(canonical_args) -> sha256` | Deterministic digest of the canonical argument object. Plaintext is never written. |
| `hash_binding(canonical_value) -> sha256` | Deterministic digest for one named sequence binding, allowing later equality comparison without plaintext retention. |
| `replay(log, lookback) -> ordered events` | Validates records and yields deterministic chronological input for reconstruction. Corrupt records fail closed and are never silently skipped. |
| `reconstruct_sequence_state(log, principal, new_session, now, lookback) -> SequenceState` | Folds within-window progress by principal, restores named binding digests, applies recorded evictions, and re-keys retained progress to the new session. Session end/idle-expiry events do not erase principal history (D15). |

Required audit event contracts:

| Event | Minimum replay/audit fields |
|---|---|
| `DecisionEvent` | Event/call ids, available session/principal identity, tool, argument digest, verdict, non-null rule id, gate class, timestamp |
| `ChainProgressEvent` | Session, principal, chain, from/to node, mapping of binding name to digest, timestamp |
| `EvictionEvent` | Session, principal, chain, evicted node, reason, timestamp |
| `SessionLifecycleEvent` | Session, optional principal, open/end/idle-expiry action, timestamp |
| `ApprovalResolutionEvent` | Approval/call ids, approved/denied/timeout status, trusted operator digest when applicable, timestamp |
| `ToolExecutionEvent` | Call id, success/failure status, result digest, timestamp |

### 4.8 Tool registry and tools

| Operation | Contract |
|---|---|
| `ToolRegistry.metadata(name) -> ToolMetadata or None` | Side-effect-free lookup used before verdict for shape validation and principal resolution. Unknown name becomes a system `DENY`. |
| `ToolRegistry.execute(name, canonical_args) -> ToolExecution` | Called only by `MonitorService` after `ALLOW` or approved `GATE`. |
| `Tool.execute(canonical_args) -> ToolExecution` | Returns raw mock-domain success/failure and JSON payload. It never constructs a `Decision` or transport `ToolResult`. |

Mock tools have no real network, filesystem, credential, or financial effects.

### 4.9 Agent and evaluation

| Operation | Contract |
|---|---|
| `Agent.run(task) -> final text` | Repeatedly asks the model for either a proposal or final text, sends proposals only through injected `Transport`, and treats every returned tool payload as untrusted model input. Final text never influences a verdict. |
| `ModelClient.next_step(task, history) -> proposal or final text` | The system's only LLM boundary. It exists only in the agent process. |
| `Scenario` | Requires exactly one MITRE ATLAS technique and allows one optional Agent-SafetyBench failure-mode tag for STAC-adapted cases. |
| `PostConditionChecker(result) -> bool` | Deterministic, scenario-specific, and LLM-free. Metric meaning remains unchanged. |

---

## 5. Import contract

| Module area | May import | Must never import |
|---|---|---|
| `src/agent` | `src/transport/contract`, `src/transport/client`, own agent modules | `src/tools`, `src/policy`, `src/monitor`, concrete transports |
| Loopback client module | Neutral transport contract/client and stdlib HTTP/JSON | Monitor, policy, audit, tools, agent |
| Loopback server adapter | Monitor service, neutral contract, stdlib HTTP/JSON | Agent |
| Verdict and sequence engines | Monitor types and immutable policy types | Audit, tools, agent, transport implementations, I/O libraries |
| Policy | Monitor value types, neutral verdict enum, stdlib, and the project's approved YAML parser; adding a parser still requires dependency approval | Service, audit, tools, agent, concrete transports |
| Audit | Monitor value types and neutral verdict enum | Policy, verdict, sequence, tools, agent |
| Tools | Raw tool value types and stdlib/mock state | Agent, policy, verdict, sequence, gate |

The import-graph test must continue to assert the complete transitive closure from every
`src.agent.*` module contains no `src.tools`, `src.policy`, or `src.monitor` module. A second
assertion for the loopback-client closure is recommended implementation evidence but does not
replace the required agent assertion.

---

## 6. Design acceptance checklist

- [x] Pure fail-closed verdict signature fixed.
- [x] Frozen `Decision` with mandatory rule id fixed.
- [x] Malformed and unknown calls have representable denial paths.
- [x] Agent-facing transport cannot create, choose, or rotate sessions.
- [x] In-process and loopback transports share one dispatch contract.
- [x] Loopback client/server import boundary fixed as a target requirement.
- [x] Live state and replay history semantics fixed under D15.
- [x] Canonical near-miss behavior fixed under D16.
- [x] Approval outcome separated from the pure `GATE` decision.
- [x] Audit ordering, hashed arguments, named binding digests, and replay inputs fixed.
- [x] Raw tool outcomes separated from agent-visible results.
- [x] D13 scenario labels and deterministic scoring represented.
- [x] State-changing loopback dispatch is explicitly documented as unsafe to retry automatically.
- [x] No dependency, policy-schema, or metric change introduced.

Implementation begins by reconciling `src/` with this document and the divergence table in
`architecture.md` §7. Functional bodies remain a later phase.
