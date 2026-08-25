# Threat Model — AI-Agent Containment Monitor

> **Final version — 2026-08-24.** Supersedes the week-one draft (2026-08-23). D9 is closed
> (indirect prompt injection is the adversary), and the decisions the week-one draft left open —
> D11 process placement and D12 state retention — are now confirmed, so §6 no longer carries
> open rows. The Phase 2 monitor core is implemented and test-proven, so §7 now records which
> goals are enforced in code today and which are designed and land in Phase 3–4 (see §10).
>
> Report placement: **Design and Development → Security Design Documentation**, immediately
> before the architecture section, because every design choice that follows is derived from it.
> Pairs with Diagram #8 (deployment / trust boundaries), Diagram #5 (single-call data flow), and
> D11 (process placement).

---

## 1. Purpose and scope of this model

This model defines who the adversary is, what that adversary can and cannot do, what the
monitor is trusted to protect, and what it does not protect. It is stated before the design
because a containment control is only meaningful relative to an adversary — a monitor that
blocks everything defeats every attacker and is useless, so the value of the design is entirely
a function of the boundary drawn here.

The model is deliberately narrow. Where a capability is excluded, it is excluded explicitly and
the consequence is stated, rather than being left as an unexamined assumption.

---

## 2. The system under consideration

The Provider operates an LLM agent that performs routine IT operations on behalf of its
technicians: reading tickets, correlating monitoring alerts, and — in the proposed extension —
executing remediations through tool calls. The agent ingests content it does not control and
emits tool calls that have real effect on systems holding protected health information.

Four components, with distinct trust levels:

| Component | Trust | Rationale |
|---|---|---|
| **Operator / technician** | Trusted | Authenticated Provider staff. Their instruction to the agent is assumed benign. |
| **Policy (YAML) and monitor code** | Trusted | Version-controlled, human-authored, reviewed. The root of the control. |
| **Agent (model + loop)** | **Untrusted** | Non-deterministic; per Zverev et al. cannot reliably separate instructions from data. Its outputs, including any justification it offers, are attacker-influenceable. |
| **Ingested content and tool results** | **Untrusted** | Ticket bodies, forwarded email, log lines, filenames, and the return values of tools. Written by parties outside the Provider's control. |

The critical line is between rows two and three. The agent is inside the system but outside the
trust boundary. This is the whole architecture in one sentence, and it is enforced structurally:
the pure verdict function `evaluate(call, policy, state)` reads the proposed call, the policy,
and the monitor-owned sequence state — never the agent's reasoning or any persuasive field it
emits (implemented; SEC-06).

---

## 3. Adversary definition

**The adversary is an external party who can place content into the data the agent reads, and
who cannot otherwise touch the Provider's infrastructure.**

Concretely, for the Provider: anyone who can cause text to appear in a support ticket, an email
forwarded into the queue, a monitored log line, or a filename on a managed endpoint. Client
staff submit tickets by design, so this surface is open by construction and cannot be closed
without removing the agent's reason to exist.

### 3.1 Adversary capabilities (what is assumed possible)

| ID | Capability |
|---|---|
| AC-1 | Insert arbitrary text into any content the agent ingests, including instructions crafted to read as directives. |
| AC-2 | Control the *return value* of a tool the agent legitimately calls, where that value derives from attacker-influenced data (a ticket body read back, a log excerpt, a directory listing containing an attacker-chosen filename). |
| AC-3 | Attempt to induce the agent to emit any tool call in the agent's registered tool set, with any arguments — including encoded, obfuscated, or look-alike arguments crafted to evade matching. |
| AC-4 | Distribute an attack across many turns and many individually innocuous tool calls, rather than requesting harm in a single step. |
| AC-5 | Know the system's design, including the policy structure and the fact that a monitor exists — Kerckhoffs applies; secrecy of the policy is not a control. |
| AC-6 | Adapt across attempts, observing which calls are refused and re-planning against the observed refusals. |

AC-4 and AC-6 are the two that most designs omit and that this project exists to test. AC-4 is
the STAC attack class; AC-6 is the adaptive attacker STAC's own authors identify as untested
against guardrails of this kind. AC-3's evasion sub-case is now directly answered in code: the
argument-aware predicates canonicalize `${IFS}` splitting, quote/backslash token-splitting,
base64 wrappers, and Cyrillic/Greek homoglyphs before matching, and use anchored full-match so a
look-alike trailing domain (`attacker@example.com.evil.com`) cannot satisfy an approved-domain
pattern (implemented and fuzz-tested; SEC-03).

### 3.2 Adversary limitations (what is assumed impossible)

| ID | Limitation | Why the assumption is reasonable |
|---|---|---|
| AL-1 | Cannot modify the model weights, the system prompt, or the agent's code. | These are Provider-controlled artifacts under change management. |
| AL-2 | Cannot read or write the policy YAML, the monitor's code, or its state. | Enforced structurally by D11's process boundary, not by convention. Holds fully under the **loopback** transport; see the caveat in §9. |
| AL-3 | Cannot authenticate to the operator console or hold valid operator credentials. | Distinct threat — see §4. |
| AL-4 | Cannot execute code on the monitor host outside the agent's tool interface. | Host compromise is a prior and larger failure; the monitor assumes an intact host. |
| AL-5 | Cannot observe or tamper with the audit log undetected. | Append-only JSONL, written by the monitor process, outside the agent's reach; a mid-file edit is surfaced on replay rather than silently skipped (implemented; SEC-07). |

Each limitation is a place where the design can be attacked in review, which is why they are
numbered. AL-2 is a genuine property only under the loopback transport, where the OS process
boundary makes tools and policy literally unimportable in the agent process; under the
in-process transport it degrades to a source-level guarantee only (§9, cross-cutting risk).

---

## 4. Explicitly out of scope

Naming these is not a weakness of the model — an unstated exclusion is the weakness.

- **A malicious or compromised operator.** The instructor's distinction is exactly this: a
  prompt-injected agent is a different adversary from a user deliberately abusing the agent.
  This project defends the former. A trusted operator instructing the agent to do harm is
  authorised action, and the monitor's response to it is the audit log, not prevention.
  *(This is the boundary STAC's published attacks sit on the far side of — hence "adapted from
  STAC", not STAC as published. See D9.)*
- **Compromise of the RMM platform itself**, independent of the agent. Pre-existing risk with
  pre-existing controls (MFA, TLS, role-based permissions).
- **Model supply-chain compromise** — a backdoored open-weight model. Mitigated in part by the
  monitor's independence: a backdoored agent still cannot execute an unpermitted call, though
  it could still exhaust the permitted action space.
- **Host and infrastructure compromise**, container escape, and side channels.
- **Denial of service** against the agent or monitor. A monitor that fails closed under load
  denies service by design; availability is not a security goal here.
- **Attacks on the agent's text output** rather than its actions — a misleading ticket summary
  shown to a technician. Progent scopes this out for the same reason; the monitor constrains
  actions, not prose.

---

## 5. Assets and attacker objectives

**Assets:** protected health information on managed endpoints; the integrity of client systems;
the RMM platform's reach across thirty practices; the audit record itself.

**Objectives an attacker would pursue, in the Provider's environment:**

1. **Exfiltration** — read PHI and transmit it outside the environment. The chained form:
   enumerate a directory → read a record → send it, each call individually within remit.
2. **Destruction** — delete or encrypt data on a managed endpoint.
3. **Persistence / privilege extension** — create an account, install a tool, alter a monitoring
   policy so future actions go unobserved.
4. **Lateral movement** — use the agent's cross-client reach to act on a second practice.
5. **Evasion** — cause a harmful action to be recorded as permitted, or not recorded at all.

Objective 5 is why auditability is a security requirement and not merely an operational one.

---

## 6. Attack surface and controls

Every surface now maps to a confirmed control; the two rows the week-one draft marked "open"
are resolved by the confirmed D11 and D12 decisions.

| Surface | Vector | Primary control | Status |
|---|---|---|---|
| Ingested content (ticket, email, log, filename) | Direct instruction injection into the agent's context | Monitor is independent of agent reasoning (SEC-06) | Implemented |
| Tool return values | Indirect injection arriving *after* the task is underway | Same; plus a dedicated red-team scenario (T5.2) | Control implemented; scenario Phase 5 |
| Tool arguments | Legitimate tool, harmful argument; encoding, traversal, look-alike evasion | Argument-aware anchored/canonicalizing matching (SEC-03) | Implemented, fuzz-tested |
| Tool sequence | Individually permitted calls composing into harm | Sequence state machine (SEC-04) | Designed (D1); lands Phase 3 |
| Approval path | Persuading or forging approval | Gate is fail-closed; agent output cannot flip GATE→ALLOW (SEC-05, SEC-06) | Verdict independence implemented; gate Phase 4 |
| Monitor state | Resetting or smearing sequence state to escape detection | D12 retention: monitor owns session identity, state reconstructed by audit-log replay keyed on `resource_principal`, evictions logged | Design confirmed (D12); replay seeding Phase 3 |
| Monitor placement | Reaching the policy object or tools directly | D11 loopback process boundary (AL-2); import-graph test is the source-level evidence | Confirmed (D11); loopback is the primary path |

---

## 7. Security goals

The monitor shall ensure that, for any agent behaviour reachable under the capabilities in §3.1:

- **G1 — Mediation.** No tool executes without a decision.
- **G2 — Fail-closed.** Absence of an explicit permission is denial.
- **G3 — Independence.** No verdict is a function of agent-produced text.
- **G4 — Sequence awareness.** A modelled malicious chain is denied at the step that completes
  it, even where every constituent call is individually permitted.
- **G5 — Reviewability.** Irreversible, high-blast-radius actions require a human decision.
- **G6 — Accountability.** Every decision is reconstructible after the fact, with the rule that
  produced it.

## 8. What the model does not guarantee

Schneider (2000) establishes that an execution monitor enforces safety properties — "nothing bad
happens" — and cannot enforce liveness. Three consequences, stated in the report rather than
discovered by a reviewer:

1. **No completeness for sequences.** The automaton recognises chains it has been taught. A
   novel chain of permitted calls will pass. This is a property of the mechanism, not a defect
   of the implementation, and it is why the evaluation reports false approval rather than
   claiming prevention.
2. **The permitted action space is still an action space.** An attacker confined to it can still
   cause harm proportionate to what the Provider chose to permit. Policy quality is a control,
   and a policy is a human artifact.
3. **False blocking is a real cost.** A monitor that denies legitimate work will be switched
   off, at which point its security value is zero. Utility is therefore measured as a security
   property, not as a usability nicety.

## 9. Residual risk

After the controls in §6, five residual risks remain. The first four descend directly from
confirmed decisions and are analysed in full in `docs/design/residual-risks.md`; each is the
price of a deliberate choice, not an implementation defect.

- **R1 — Low-and-slow chains (from D12.4).** A chain paced so its recon prefix falls *outside*
  the audit-log lookback window (default 24 h) presents a fresh session whose replay-seeded
  state has forgotten the prefix, so the terminal `transfer_funds` is judged only per-call. The
  window is a tunable, logged detection horizon, not a guarantee; snapshotting is the named
  future work that lengthens it without unbounded replay.
- **R2 — Novel unmodelled chains (from D1).** A bounded automaton recognises exactly the chains
  encoded in its `ChainSpec`s; a harmful composition it was never taught passes the sequence
  layer and is judged only per-call. Inherent to the mechanism (Schneider 2000). The per-call
  layer and the D5 gate remain as a backstop; provenance/taint tracking is the deferred mechanism
  that would close it.
- **R3 — Subject-cardinality pressure (from D12.5).** Per-subject chain caps evict
  least-advanced-first and log every eviction, but nothing caps the *number* of subjects; an
  attacker spreading shallow progress across many mock accounts avoids the per-subject cap. The
  residual is availability (memory and replay I/O), accepted at capstone scale; production would
  apply per-tenant quotas.
- **R4 — Replay cost as the log grows (from D12.4).** Reconstructing state means replaying the
  audit log over the lookback window; the single un-rotated JSONL grows without bound. Accepted
  at capstone scale; log rotation plus re-derivable snapshots (kept as a cache, never a second
  source of truth) is the named future work.
- **Cross-cutting — in-process transport is weaker than loopback (from D11).** The import-graph
  test proves the agent has no *source-level* path to `tools`/`policy`, but source isolation is
  not memory isolation. AL-2 is a full property only under the loopback transport, where the OS
  process boundary applies. Loopback is therefore the D11 primary path; in-process is a labelled
  CI/demo convenience, and the tamper-resistance claim is stated as holding under loopback.

Beyond these mechanism-level residuals, the Provider retains operational risk from a compromised
operator account (out of scope, §4), risk proportional to the breadth of the authored policy,
and risk that a fatigued reviewer approves a GATE without scrutiny (Turan 2026 — the reason the
gate is scoped to four irreversible classes rather than applied broadly). These are accepted,
documented, and revisited on the review cadence defined in the maintenance plan.

## 10. Implementation status of the goals

The threat model is validated by code, not asserted. As of the completed Phase 2 monitor core:

| Goal | Requirement | Status | Evidence |
|---|---|---|---|
| G1 Mediation | SEC-01 | Design complete; dispatch wiring Phase 3–4 | `evaluate` is the sole verdict path; mediated dispatch lands with the banking domain (#11) |
| G2 Fail-closed | SEC-02 | **Implemented, test-proven** | Default DENY on no match; unknown tool and empty policy deny all |
| G3 Independence | SEC-06 | **Implemented, test-proven** | Pure `evaluate` reads only call/policy/state; verdict cannot be flipped by agent text |
| G4 Sequence awareness | SEC-04 | Designed (D1); Phase 3 | `classify`/`advance` land with the kill-chain automaton (#10–#12) |
| G5 Reviewability | SEC-05 | Designed (D5); Phase 4 | Four GATE classes route to the operator console (#13–#14) |
| G6 Accountability | SEC-07 | **Implemented, test-proven** | Append-only JSONL, traceable `rule_id` per decision, hashed arguments, replay + tamper detection |

Argument awareness (SEC-03) is likewise implemented and fuzz-tested. The goals still marked
"designed" are constrained by confirmed decisions and existing interfaces, not open questions;
their controls are drawn in Diagram #5 and specified in `docs/design/`. This section is updated
as each subsequent phase closes.
