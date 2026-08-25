# ARCHIVAL WORKSHEET — NOT CURRENT DECISION STATE

> Retained only as the 2026-08-23 drafting worksheet. Its proposed/open blocks were superseded by
> the confirmed entries in [`Decision Log.md`](Decision%20Log.md), the sole authoritative decision
> record. Do not use this file to determine current D9–D17 status.

# Entries to paste — 2026-08-23 (instructor approval)

Three blocks below. **A** and **B** go into `Decision Log.md`; **C** goes into
`capstone/Capstone Check-ins.md` above the 2026-08-19 entry.

---

## A. Replace the existing D9 block with this

## D9 — Threat model reconciliation (CLOSED)
**Decision:** **Option (b) — indirect prompt injection.** The operator is trusted and the
task is benign; the adversary controls content that *reaches* the agent through ingested
data and tool results — ticket bodies written by client staff, forwarded email, log lines,
filenames. STAC's chain *structures* are re-homed as indirect injection and cited as
**"adapted from STAC"**, never as STAC as published.
**Status:** **Confirmed (2026-08-23)**, on instructor direction.

**What closed it.** Dr. Alzoubi's Idea Approval feedback (Canvas, 2026-08-23): *"Define your
threat model in week one. A prompt-injected agent is a different adversary than a user
deliberately abusing the agent. Your policy follows from that assumption."* The MSP case
study already forces the choice — the Provider's operators are its own technicians, and the
untrusted content is client-authored ticket text arriving through the queue.

**Consequences to carry into the report:**
- Progent's benign-user threat model is **retained**, so the D7 comparison stays like-for-like.
  The option (a) rewording of D7 is no longer needed.
- STAC's 91.2% ASR remains citable as evidence of the **attack class**, not as a baseline this
  project's numbers can be compared against. State that explicitly in the evaluation chapter —
  the setups do not match and a naive comparison would be indefensible.
- At least one **indirect-injection-via-tool-result** scenario becomes mandatory
  (`todo.md` T5.2; `qa-redteam-plan.md` gap #2). It is no longer a nice-to-have; it is the
  scenario that demonstrates the chosen threat model.
- **Explicitly out of scope, and say so:** a compromised operator account, a shared-agent
  credential, or a deliberately abusive authorised user. Name this as a limitation in the
  report rather than letting a reviewer find it.
- Note the shared boundary honestly: STAC's own Limitations observe that control-flow
  separation defenses aimed at untrusted tool output *"do not target STAC's vector—in which
  the adversary acts through the trusted user channel itself."* This project sits on the same
  side of that line. One sentence, stated plainly, costs nothing and pre-empts the question.

---

## B. Append these two new entries to `Decision Log.md`

## D11 — Monitor placement / process boundary
**Decision:** The monitor runs as a **separate process**, and the policy engine is the **only**
path to tools. Tools are imported by the monitor process; the agent process holds no import
path to them and reaches them solely through a local decision endpoint.
**Status:** **Proposed / needs Luis's confirmation (raised 2026-08-23).** Blocks T2.1 scaffold —
this determines the dispatch layer, so decide before the repo layout is fixed.

**What raised it.** Instructor feedback, 2026-08-23: *"Say where the monitor sits. If it shares
a process with the agent, the agent can reach it. A separate process with the policy engine as
the only path to tools is safer. Justify your choice."* The current `spec.md` §4/§6 assumes
in-process mock tools, so this is a change, not a confirmation.

**Alternatives weighed:**
- *In-process monitor and tools* (the previous assumption) — simplest, fastest, no IPC. But the
  agent shares an address space with both the tool functions and the live policy object, so
  **tamperproofness cannot be claimed or tested**. Rejected.
- *Separate monitor process; local HTTP/IPC decision endpoint; tools behind it* — Flask is
  already in the stack for the console (`spec.md` §4), so the marginal cost is small. Makes the
  trust boundary structural rather than conventional. **← chosen**
- *Container / network isolation* — strongest form of the same argument, but deployment
  complexity and Windows build-box friction against an end-of-October build. Keep as a
  **deployment-chapter recommendation and future work**, which is also a free "Review and
  Continuous Improvement" paragraph.

**Why:** Anderson (1972) requires a reference monitor to be complete, **tamperproof**, and
verifiable. Complete mediation is criterion #1 and already test-proven; verifiability comes
from the audit log. Tamperproofness currently has **no test at all**, because in-process there
is nothing to test — the property is asserted, not held. A process boundary is what converts it
into a structural property with a test behind it.

**Implications to propagate:**
- `spec.md` §4 and §6 — tools move behind the monitor process; the agent gets a thin client.
- **Diagram #8 (deployment / network zones)** becomes a real trust boundary rather than
  decoration. This lands in the 25-point Design section, so the decision pays for itself twice.
- **SR-08** (50 ms p95) — loopback IPC adds roughly 1–3 ms, comfortably inside budget, but
  measure it and report the measured figure rather than the assumption.
- **New test:** an import-graph assertion that `src/agent` has no path to `src/tools`. Cheap,
  and it is the direct evidence for the tamperproof claim in the report.
- **Scope-cut position:** if the boundary threatens the Phase 3 schedule, degrade to in-process
  with the threat-model caveat documented — do not lose the sequence engine to it. Insert above
  item 3 in `spec.md` §11.

---

## D12 — Sequence-state retention policy (OPEN)
**Decision:** *Not yet made.*
**Status:** **Open / raised 2026-08-23.** Blocks T3.1.

**What raised it.** Instructor feedback: *"think about how much state the monitor keeps."* D1
settled the *mechanism* (explicit kill-chain automaton) but never specified the **retention
policy**, and `qa-redteam-plan.md` T4.2 already lists session-reset abuse and cross-session
smear as evasions the design must survive. Those tests cannot be written until this is answered.

**The questions to answer, each with a report sentence attached:**
- **Scope key** — is sequence state keyed to the agent session, the task, the operator, or the
  target account? The banking chain smears across sessions if the key is too narrow.
- **Lifetime** — does state expire on a timer, on task completion, or never within a run?
- **Reset authority** — can *anything the agent does* clear state? Per `spec.md` §10 Boundaries
  the answer must be no, but that has to be enforced, not assumed.
- **Persistence** — in-memory only, or written alongside the audit log so a chain split across
  two runs is still detectable? Persistence buys the cross-session-smear defense and costs a
  storage and privacy question.
- **Bound** — what stops unbounded growth? An eviction policy is a security decision, because
  eviction is exactly where an attacker will aim.

**Note for the report:** this is the "how much state" question stated as a design trade-off —
more retention catches more chains and increases both false-block risk and the value of the
state store as an attack target. Presenting it as a reasoned trade-off rather than an
implementation detail is what makes it read as design work.

---

## C. Add to `capstone/Capstone Check-ins.md`

## 2026-08-23 — Idea Approval graded: **APPROVED**
- Dr. Alzoubi approved via Canvas comment (Aug 23, 6:10 PM): *"Approved. Proceed with this
  project."* No scope change requested. Closes the `todo.md` carry-over item on instructor
  sign-off, and closes `spec.md` §12's open item on topic approval.
- **Confirmed correct:** the framing (an independent control that judges actions rather than
  trusting what the agent was told) and the NIST CSF / OWASP LLM mappings as "the grounding the
  rubric expects."
- **Contribution confirmed by the instructor:** *"Multi-step sequences are your real
  contribution… Give it its own section."* → **D10 (novelty vs concurrent work) is retired as a
  grading risk.** Related Work still cites ePCA / DSCC / MAGE honestly, but the claim no longer
  has to be narrowed to survive review.
- Also confirmed: track false denials alongside false approvals — already success criterion #6,
  no change needed.
- **Report structure change:** sequence evaluation needs its **own report section**. `plan.md`
  Phase 3 currently distributes it across Design and Implementation. Give it a named heading.
- **New work generated:**
  - **D11** — monitor placement / process boundary. **Blocks T2.1.**
  - **D9** — closed as option (b), indirect injection. **Unblocks Task 14 / T5.2.**
  - **D12** — sequence-state retention. **Blocks T3.1.**
- ⚠️ **Carry-over risk still live.** The approval was of the proposal *as written*, which
  contains the "genuine, unsolved need" claim. Approval is not validation of that sentence — it
  must still not survive into the Project Report (`research.md` § Positioning statement).
- "Keep it technical." The case-study chapters are rubric-mandated and stay, but the remaining
  depth budget belongs in Design and Implementation (45 points). Company profile and cost model
  are complete; do not expand them.
