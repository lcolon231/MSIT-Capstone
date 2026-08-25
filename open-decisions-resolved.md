# Open decisions — proposed resolutions, 2026-08-23

Four decisions remain unresolved: **D10**, **D11**, **D12**, and the scenario-labelling
question (promoted here to **D13**). Below is a proposed answer for each, in the Decision Log's
format. All are marked `Proposed` — change to `Confirmed` when you've agreed with them.

Everything else previously listed as open is already settled: D9 closed as indirect injection,
D4 model, D6 scoring, scope-cut order in `spec.md` §11, due dates and topic approval both
confirmed. The remaining items in `todo.md` — Canvas group weights, ROI calculation, AI
disclosure — are tasks, not decisions, and stay where they are.

---

## D10 — Novelty scope vs concurrent work (CLOSED)
**Decision:** Close without further reading. The contribution is stated as **integration and
adversarial evaluation**, not a new mechanism: deterministic, inspectable, policy-as-data
sequence enforcement, on a local open-weight agent, under an indirect-injection threat model,
scored deterministically. Concurrent systems are cited honestly in *Review of Existing
Technologies* and differentiated on those four properties.
**Status:** **Proposed / Confirmed (2026-08-23)** — closing, not deferring.

**What closed it.** Two things. The instructor named the contribution directly — *"Multi-step
sequences are your real contribution"* — and there is no rubric line for novelty or related
work anywhere in Assignment 1. The literature already appears in the drafted Phase 1 chapter
(ePCA, DSCC, MAGE, ARGUS, CaMeL), which is the only place it is graded, inside a five-point
section.

**What this explicitly rules out:** reading the concurrent guardrail papers beyond the abstracts
already reflected in `research.md` and the drafted chapter. That work has no marginal value
against this rubric, and the ~1 week it would consume belongs to Design and Implementation,
which are 45 points.

**The honest claim to make in the report, and its limit.** The mechanism class is established
prior art; this project does not claim to have invented sequence-aware enforcement. What it
claims is a working control built for a specific environment and evaluated on false approval,
false blocking and utility together — which DSCC does not report and ePCA does not test
adversarially. If a reviewer names a system this project did not compare against, the answer is
that comparison was out of scope, not that the system was unknown.

---

## D11 — Monitor placement / process boundary
**Decision:** **Separate process.** The monitor process owns the policy, the sequence state and
the tool implementations, and exposes a local decision-and-dispatch endpoint on loopback. The
agent process holds no import path to `src/tools` and no reference to the policy object. Tools
are invoked *by the monitor after a verdict*, never by the agent.
**Status:** **Proposed (2026-08-23).** Confirm on the instructor's reply, but build behind the
swappable transport now — the design work is identical either way.

**Alternatives weighed:**
- *In-process monitor and tools* (previous spec assumption) — no IPC, fastest to ship. Rejected:
  the agent shares an address space with the policy object and the tool functions, so
  tamperproofness cannot be claimed, let alone tested. The instructor raised this specifically.
- *Separate process over loopback HTTP, tools behind it* — Flask is already a dependency for the
  console, so the marginal cost is one small app and a thin client. Makes the trust boundary
  structural. **← chosen**
- *Separate containers with no shared filesystem* — the strongest version, and the right
  recommendation for a real deployment. Rejected for the build: Windows container friction
  against an end-of-October deadline. Carry it into the report as a deployment recommendation
  and future work.

**Why:** Anderson (1972) requires a reference monitor to be complete, tamperproof and
verifiable. Complete mediation is criterion #1 and test-proven; verifiability comes from the
audit log. Tamperproofness currently has no test, because in-process there is nothing to test —
it is asserted, not held. The boundary converts an assumption (AL-2 in the threat model) into a
property with evidence behind it.

**Design consequence that matters:** the agent never calls a tool. It *proposes* a call, and the
monitor executes it if the verdict permits. This is stronger than mediation-by-convention and it
is a clean sentence for the report.

**Propagate to:**
- `spec.md` §4 and §6 — tools move under the monitor process; agent gets a thin client
- Diagram #8 becomes a real trust boundary
- **SR-08** — measure loopback overhead (expect 1–3 ms) and report the measured p95, not the
  assumed one
- New test: import-graph assertion that `src/agent` cannot reach `src/tools`
- `spec.md` §11 — insert as scope-cut item 0: degrade to in-process **with the threat-model
  caveat documented**, before cutting anything else

---

## D12 — Sequence-state retention policy
**Decision:** Five parts, each answering one of the questions raised on 2026-08-23:

1. **Key.** State is keyed on a **composite of session and subject** — the monitor-assigned
   session identifier plus the resource principal the chain acts against (account, endpoint,
   client). Chains progress per subject, so acting on two different accounts does not
   accidentally advance one automaton.
2. **Session identity is assigned by the monitor.** The agent cannot supply, choose or rotate a
   session id. This single rule is what defeats session-reset abuse; without it, that evasion
   works trivially and the automaton is theatre.
3. **Reset authority.** Nothing the agent does clears state — no tool call, no argument, no
   declaration that a new task has begun. State clears only on monitor-side session end or idle
   expiry (default 30 minutes, configurable, logged when it fires).
4. **Cross-session persistence via the audit log.** Chain-progress events are already decisions,
   and the audit log is already append-only. On startup the monitor **replays the log** to
   reconstruct per-subject chain progress within a configurable lookback window (default 24
   hours). No second datastore, no new schema, and tamper-evidence comes free.
5. **Bound.** Cap tracked chains per subject; evict least-advanced first, and **write the
   eviction to the audit log as its own event**. Eviction is where an attacker will aim, so it
   must be visible rather than silent.
**Status:** **Proposed (2026-08-23).** Blocks T3.1 until confirmed.

**The trade-off, stated for the report:** retention is a dial. More of it catches more chains —
particularly cross-session smear — and costs more false blocks, more storage, and a larger
attack surface around the state store itself. This design sits deliberately toward the
conservative end: session-scoped by default, with a bounded 24-hour cross-session window rather
than indefinite memory.

**Evasion coverage** (each has a test in `qa-redteam-plan.md` T4.2):

| Evasion | Defeated by | Residual |
|---|---|---|
| Interleaving benign calls | State advances on matching calls only; noise is ignored | None |
| Reorder / partial chain | Transition table accepts defined partial orderings | Novel orderings pass — inherent to D1 |
| Session reset abuse | Part 2 — monitor assigns session identity | None |
| Duplicate / idempotent steps | Idempotent transitions; repeats do not advance | None |
| Cross-session smear | Part 4 — 24-hour replay window | A chain paced slower than the window passes |
| Eviction abuse | Part 5 — least-advanced-first, eviction logged | Attacker with many subjects can pressure the cap |

The two residuals are real and go in the limitations section. Both are consequences of a bounded
automaton, which Schneider (2000) predicts; neither is a defect to hide.

**Honest cost of part 4:** log replay on startup grows linearly with the log, and a long-running
deployment needs log rotation with a state snapshot. For a capstone-scale evaluation this never
bites, but say so rather than implying the design scales unexamined.

---

## D13 — Scenario labelling scheme
**Decision:** **MITRE ATLAS as the primary label**, one technique per scenario. Where a scenario
is adapted from STAC, carry its **Agent-SafetyBench failure mode** as a secondary tag.
**Status:** **Proposed (2026-08-23).** Promoted from the "still-open" list in the Decision Log.

**Why:** ATLAS is the security-standard vocabulary and sits naturally alongside the NIST CSF 2.0
and OWASP LLM mappings the instructor named as the grounding the rubric expects — three
recognised frameworks telling one story is worth more here than a taxonomy from a single paper.
The `qa-redteam-plan.md` ATLAS table is already written (AML.T0053, T0051, T0051.001, T0057), so
this costs nothing. The secondary tag preserves traceability back to STAC for the adapted chains
and is one extra optional field in the scenario metadata.

**Rejected:** Agent-SafetyBench's ten failure modes as the primary scheme — accurate and
research-legible, but it maps to nothing else in the report and would need explaining from
scratch. Using both as co-equal primaries doubles the labelling work for no gain.
