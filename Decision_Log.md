# SUPERSEDED — DO NOT USE AS CURRENT DECISION STATE

> This underscore-named file is retained only for provenance. It was superseded on
> **2026-08-24** by [`Decision Log.md`](Decision%20Log.md), which is the sole authoritative
> decision record. In particular, the D11/D12 entries below are stale: D11–D17 are confirmed in
> the authoritative file. Do not use this file to determine implementation or design status.

# Decision Log — AI-Agent Containment Monitor Capstone

Decisions + rationale for the build. Companion to `research.md` (literature) and the
spec. Each entry records the choice, the alternatives weighed, and why. Update the
**Status** line when a proposed decision is confirmed, changed, or superseded.

Status legend: `Proposed` (Claude's recommendation, awaiting Luis's confirmation) ·
`Confirmed` · `Changed` · `Superseded`.

---

## D1 — Sequence evaluation approach
**Decision:** Explicit state machine (kill-chain-aligned automaton).
**Status:** Confirmed (2026-08-18). **Reinforced 2026-08-19** — see D7; AgentSpec §6.3
names this exact gap as its own limitation and proposes a *probabilistic* fix (DTMC
reachability). Choosing a deterministic automaton instead is now a positioned design-space
argument rather than merely a scoping choice. **Endorsed 2026-08-23** — the instructor names
multi-step sequences as "your real contribution" and asks for it to have its own report
section. The *mechanism* is settled here; **how much state it retains is not, and is now
tracked separately as D12.**

**Alternatives weighed:**
- *Explicit state machine* — implements the novelty claim directly; explainable and
  diagrammable; maps to ChainWatch's fraud chain; bounded/finishable. Limitation: only
  catches pre-modeled chains (citable via Schneider 2000, not a hidden flaw). **← chosen**
- *Sliding-window heuristics* — least code, but fuzzy verdicts, weak explainability,
  arbitrary window size. Undercuts the "inspectable policy" claim.
- *Provenance / taint tracking* — most rigorous but = re-implementing CaMeL, which
  `research.md` marks out of scope / upper bound. High risk to the Oct deadline.
- *Probabilistic foresight (DTMC reachability)* — **AgentSpec's own proposed future work**,
  added here 2026-08-19 for completeness. Rejected: a probabilistic verdict reintroduces the
  non-determinism the monitor exists to remove, cannot be inspected as version-controlled
  policy, and would breach the spec rule that no probabilistic component sits in a success
  metric. Cite it in the report and say why deterministic automata were chosen instead.

**Why:** It *is* the contribution, it is demonstrable, it is finishable, and its
limitation is one to cite rather than hide. Provenance becomes future work.

**External endorsement (added 2026-08-19, from STAC's Limitations → Defense scope):** STAC's
authors note their stealth metrics "do not test sequence-level monitors such as audit-log,
action-pattern, or state-diff analysis." The benchmark's own authors flag this class of
defense as untested. Cite in the motivation.

---

## D2 — Policy representation
**Decision:** Narrow custom YAML schema; trigger/predicate/enforcement *structure*
consciously borrowed from AgentSpec (arXiv:2503.18666) for the citation without the
integration cost. Sequence rules reference the D1 state machine.
**Status:** Confirmed (2026-08-18). **Evidence strengthened 2026-08-19** (full AgentSpec read).

**Alternatives weighed:**
- *Narrow custom YAML* — fastest; declarative data = inspectable, version-controllable
  policy, which *is* the "independent policy" argument; no dependency friction. Risk:
  schema scope-creep (mitigate with a hard field freeze). **← chosen**
- *Adapt AgentSpec DSL wholesale* — borrowed rigor + citation, but targets code agents
  not tool-call chains; more parsing overhead; inherited complexity.
- *Python-callable predicates* — maximally expressive, but policy becomes code, which
  weakens the central claim that the monitor is an auditable layer separate from agent
  logic. Harder to red-team the policy itself.

**Why:** Declarative policy-as-data is the strongest form of the independence argument
and the fastest to ship. Borrowing AgentSpec's structure buys rigor cheaply.

**Supporting evidence (added 2026-08-19):**
- AgentSpec §6.2: rule enforcement "is declarative and externalized from the LLM, ensuring
  consistent behavior across runs, environments, and model versions." Policy-as-data is the
  design an ICSE paper argues for on reproducibility grounds — not an idiosyncratic choice.
- AgentSpec §6.1: "an external, developer-defined enforcement model… This explicit separation
  between the agent's reasoning and its safety enforcement mechanism improves verifiability
  and robustness." That is this project's independence claim, already peer-reviewed. Quote it.
- Progent likewise keeps its LLM in the policy-*authoring* role and out of the enforcement
  path.
- AgentSpec's LLM-generated rules scored precision 95.56% but **recall 70.96%** — ~29% of
  unsafe cases missed. Empirical argument for hand-authored policy over generated policy.

**Concrete structure confirmed from the paper** (use as the schema reference):
`rule @name / trigger <event> / check <predicates> / enforce <actions> / end`, where
predicates are named domain-scoped functions (`is_destructive_cmd`, `!has_access(role,
resource)`, `obstacle_distance_leq(n)`) and general triggers are *state change*, *action*
(fires pre-execution), and *agent_finish*.

---

## D3 — Red-team evaluation harness
**Decision:** Custom tool suite + chained-attack scenarios adapted from STAC
(arXiv:2509.25624), as the primary harness. Tool interface designed so AgentDojo can be
bolted on later (first stretch / scope-restore goal). Report false-approval,
false-block, and utility metrics.
**Status:** Confirmed (2026-08-18). ✅ **Unblocked 2026-08-23** — D9 closed as option (b),
so STAC chains are re-homed as indirect injection and cited as **"adapted from STAC"**, never
as STAC as published. Task 14 may proceed.

**Alternatives weighed:**
- *Custom + STAC chains* — self-contained, no Windows harness fight; tailored to the
  policy and state machine; STAC supplies the gap statement and 483 adaptable attack
  patterns. Risk: home-grown metrics need careful definition. **← chosen**
- *Integrate AgentDojo* — standardized citable metrics + credibility, but heavy
  integration and single-call-attack oriented — does not exercise the sequence claim.
- *Both* — strongest eval chapter, highest deadline risk; realistic chance neither is
  polished by end of October.

**Why:** STAC directly tests the sequence contribution; AgentDojo does not. Keep the
door open to AgentDojo cross-validation as a stretch goal, not a dependency.

**Findings from the full STAC read (2026-08-19):**
- Released data and code: <https://github.com/amazon-science/MultiTurnAgentAttack>. Check the
  repo for reusable **RMM** chains before authoring scenarios from scratch (Task 14).
- STAC's environments come from **SHADE-Arena** (Kutasov et al. 2025, which extends
  AgentDojo): RMM, Travel, Workspace, Spam Filter Updating — plus 62 simpler environments
  sampled from **Agent-SafetyBench** (Zhang et al. 2024), whose **10 agent-specific failure
  modes** are STAC's labelling scheme. Decide whether to label scenarios with those, with
  ATLAS techniques (per `qa-redteam-plan.md`), or both.
- STAC's own metrics are **ASR** (attack success), **PH** (prompt harmfulness), **RR**
  (refusal rate), reported per turn (T, T+1, T+2). Align criterion #6 vocabulary with these
  rather than inventing new names; ASR climbing across turns is itself sequence evidence.
- Baseline to beat: **no prompt-based defense is sufficient.** Their best (a harm–benefit
  Reasoning prompt) cuts ASR 87.4% → 58.6% at first turn but erodes under adaptation;
  ToolShield is the most durable at T+2 (78.1%). Do not claim a numeric comparison against
  these without matching the setup.

---

## D4 — Local model + runtime
**Decision:** Ollama + Llama 3.1 8B as the concrete build target, behind a thin
pluggable model interface (any Ollama tool-calling model swappable later).
**Status:** Confirmed (2026-08-18).

**Build hardware (confirmed 2026-08-18):** Desktop — i7-12700K, 32 GB RAM,
RTX 4060 (8 GB VRAM). At Q4_K_M: Llama 3.1 8B (~6–6.5 GB) and Qwen2.5 7B (~5.5–6 GB)
run fully GPU-resident with context headroom. Qwen2.5 14B (~10–11 GB) exceeds 8 GB VRAM
and would partially offload to CPU — usable but slow; keep as an optional stronger-agent
experiment only. Spec assumes GPU-resident 7–8B inference; no CPU-fallback hedging needed.

**Alternatives weighed:**
- *Ollama + Llama 3.1 8B* — lowest-friction on Windows; reliable tool-calling; runs on
  modest hardware; large support community. A fallible agent is *desirable* for a
  containment project. **← chosen**
- *Ollama + Qwen2.5 7B/14B* — excellent function-calling; 14B needs ~10GB+ VRAM, may not
  fit; marginal benefit for a monitor built to contain a cheap, fallible agent.
- *Defer choice entirely* — clean abstraction but a scheduling risk; still need a
  concrete target from day one.

**Why:** Gives a real model to build against immediately while the interface preserves
swap-ability — resolving `research.md`'s open question without deferring it.

**Note (2026-08-19):** STAC found its attack effective across 8 agents in 4 families, both
open-weight and frontier, concluding the vulnerability "is not tied to specific architectures
or model scales." Useful cover for the local-open-weight choice — a reviewer cannot dismiss
the target model as unrepresentative of the vulnerability class.

---

## D5 — Human-approval gate set
**Decision:** The gate fires for exactly four irreversible/high-blast-radius operation
classes: **file delete, network send/exfil, data export, credential access.** All other
tool calls are allow/deny only (no gate).
**Status:** Confirmed (2026-08-18).

**Why:** Kept deliberately small. Turan (2026, arXiv:2606.08919) models the reviewer as
fatiguing, not an infinite oracle — a wide gate degrades into rubber-stamping, which is
worse than no gate. Scoping to irreversibility × blast radius keeps each prompt meaningful.

**Precedent (added 2026-08-19):** AgentSpec's `user_inspection` enforcement action is the
direct analogue of `GATE`, and its worked example gates a **financial transfer** on a
recipient predicate (`rule @inspect_transfer / trigger Transfer / check
!is_to_family_member / enforce user_inspection`) — near-identical to this project's RMM
domain. Cite it rather than re-deriving the justification.

**External endorsement (added 2026-08-19):** STAC's Limitations name "action-level policies
such as user confirmation for destructive actions" as something that "could provide stronger
protection and are important future directions." The benchmark's authors endorsing this exact
design is the strongest available motivation citation for D5.

*Contrast worth a sentence in the report:* Progent also gates on human approval, but gates
*policy expansions* rather than individual actions. Two different answers to the same
alert-fatigue problem.

---

## D6 — Escape scoring
**Decision:** A **custom deterministic checker per scenario**, mirroring AgentDojo's
state-based approach: each red-team scenario declares a concrete post-condition (e.g.
"records exported to an attacker destination", "file X deleted", "secret read into an outbound call").
The checker inspects the recorded tool-call log / mock-tool state and returns a binary
escape / no-escape verdict.
**Status:** Confirmed (2026-08-18). **Vindicated 2026-08-19** by STAC's own limitations.

**Why:** Deterministic, reproducible, and defensible in the report — no LLM-judge
non-determinism in the metric that decides success. False-approval is then simply: an
escape post-condition was reached while the monitor returned ALLOW.

**Supporting evidence (added 2026-08-19):** STAC scores attack success with a **GPT-4.1 Judge
that shares a model family with its Generator and Planner**, and concedes: "a single-family
judge may shape the reported ASR, PH, and RR", treating human validation and cross-family
judging as important next steps. STAC also reports **single-run point estimates** with
run-to-run variance uncharacterised, warning that small gaps between defenses "should be read
with caution."
→ Two honest methodological improvements this project can claim over the benchmark it adapts
from: (1) deterministic per-scenario checkers instead of an LLM judge, and (2) multi-seed runs
with variance reported. Both are cheap and both are conceded weaknesses in the source.

---

## D7 — Related Work positioning claim (how this project differs from prior art)
**Decision:** Differentiate on **checkpoint enforcement vs. trajectory reasoning**, anchored
in each paper's own words. Retire the earlier wording "these systems evaluate each call in
isolation."
**Status:** Confirmed (2026-08-19), after reading Progent and AgentSpec in full.
Concurrent work still needs honest citation (D10), but as of 2026-08-23 it no longer threatens
the positioning — the instructor has named multi-step sequences as the contribution.

**The three-citation argument, in the order to present it:**
1. **AgentSpec §6.3 "Limitations and Future Work"** — verbatim: *"AgentSpec currently
   performs deterministic enforcement at discrete execution checkpoints… it does not reason
   about the long-term consequences of current actions. Specifically, AgentSpec lacks support
   for trajectory-based safety analysis, i.e., estimating whether an action sequence might
   lead to unsafe states several steps into the future."* An explicit concession, in an ICSE
   2026 paper, that names this project's contribution as prior art's own limitation.
   **Lead with this.**
2. **Progent, "Progent's Defense Scope"** — verbatim: *"Progent cannot be used to defend
   against attacks that operate within the least privilege for accomplishing the user task."*
   The same gap, stated as scope. A chain of individually-permitted calls is by construction
   that class.
3. **STAC** — that attack class succeeds **91.2%** of the time across 483 verified cases;
   their conclusion, verbatim: *"defending tool-enabled agents requires reasoning over entire
   action sequences and their cumulative effects, rather than evaluating isolated prompts or
   responses."*

Prior art concedes the gap; the benchmark shows it is exploited at scale; this project builds
and red-teams the mechanism.

**Alternatives weighed:**
- *"Checkpoint enforcement vs. trajectory reasoning"* (AgentSpec's own vocabulary), plus
  *"privilege state vs. sequence state"* for Progent — precise, sourced, survives review.
  **← chosen**
- *"Prior systems evaluate each call in isolation"* (previous wording) — **rejected as
  inaccurate.** Progent's policy updates during execution; AgentSpec's predicates are formally
  defined over the trajectory `τ_i` (Definition 3.1). Leaving this in would have put a
  falsifiable error at the centre of the novelty claim.
- *"AgentSpec cannot express cross-call conditions"* — **rejected as unsupported.**
  Definition 3.1 types every predicate as `p_r(u, τ_i)`, taking the whole trajectory. What is
  true is narrower: the paper's defined predicates take only current state `s_i` and current
  action `a_i`, and the authors concede the trajectory gap themselves. Quote §6.3; do not
  overreach past it.
- *"Progent is memoryless / keeps no call history"* — **rejected as unsupported.** The paper
  does not state either way.

**Honest caveats to preserve in the report:**
- Progent's Discussion never raises sequential or chained calls. Its limitation *follows from*
  the stated scope — do **not** claim its authors acknowledge chained attacks. AgentSpec's
  concession is the explicit one; lean on that.
- AgentSpec proposes closing the gap *probabilistically* (DTMC + probabilistic reachability).
  This project answers the same gap deterministically (D1). Acknowledge their direction and
  argue the deterministic choice — see D1.

---

## D8 — Enforcement-action subset
**Decision:** Implement only the **suppression subset** of AgentSpec's enforcement actions:
`DENY` (≈ action termination / `stop`) and `GATE` (≈ `user_inspection`). Do **not** implement
`llm_self_examine` (self-reflection) or `invoke_action` (corrective invocation).
**Status:** Confirmed (2026-08-19).

**Why:** Both excluded actions operate *on the agent* — they change what it does next.
The spec's Boundaries forbid the monitor from reaching into agent state, and the independence
claim depends on the verdict being a pure value returned to the caller. `llm_self_examine`
additionally puts an LLM back inside the enforcement path, which the "no LLM judge" rule
forbids outright.

**Framing for the report:** Ligatti, Bauer & Walker's edit automata give the clean vocabulary
— suppression and termination are in scope; insertion/correction is not. State this as a
deliberate design choice with its reason, or a reviewer comparing against AgentSpec will read
a two-of-four implementation as an omission.

---

## D9 — Threat model reconciliation (CLOSED)
**Decision:** **Option (b) — indirect prompt injection.** The operator is trusted and the task
is benign; the adversary controls content that *reaches* the agent through ingested data and
tool results — ticket bodies written by client staff, forwarded email, log lines, filenames.
STAC's chain *structures* are re-homed as indirect injection and cited as **"adapted from
STAC"**, never as STAC as published.
**Status:** **Confirmed (2026-08-23)**, on instructor direction. Unblocks D3 / Task 14 / T5.2.

**What closed it.** Idea Approval feedback (Canvas, 2026-08-23): *"Define your threat model in
week one. A prompt-injected agent is a different adversary than a user deliberately abusing the
agent. Your policy follows from that assumption."* The MSP case study already forces the
choice — the Provider's operators are its own technicians, and the untrusted content is
client-authored ticket text arriving through the queue.

**Consequences to carry into the report:**
- Progent's benign-user model is **retained**, so the D7 comparison stays like-for-like. The
  option (a) rewording of D7 is not needed.
- STAC's 91.2% ASR remains citable as evidence of the **attack class**, not as a baseline this
  project's numbers can be compared against. Say so explicitly in the evaluation chapter.
- At least one **indirect-injection-via-tool-result** scenario is now mandatory (`todo.md` T5.2,
  `qa-redteam-plan.md` gap #2). It is the scenario that demonstrates the chosen threat model.
- **Explicitly out of scope, and stated as such:** a compromised operator account, a shared-agent
  credential, or a deliberately abusive authorised user.
- Full write-up: `docs/design/threat-model.md`, for the report's Security Design Documentation
  section.

**The reconciliation problem, retained for the report's rationale.** Two threat models were in
play and they are incompatible:

- **Progent's** (adopted in D7's knock-on): *"the user is benign, and as such, the user's
  input query is always benign"*; the attacker manipulates external data sources reaching the
  agent; cannot alter weights or system prompt. This is the **indirect prompt injection** model.
- **STAC's** (§2.1): *"The adversary issues prompts directly through the user-facing interface
  (e.g., via a compromised account, shared agent, or delegated access). We evaluate this
  direct-access setting and leave indirect prompt injection to future work."* The adversary
  **is** the user channel.

D3 plans to adapt STAC chains into the red-team suite. That cannot be done without picking one
of these — the attacks do not transfer for free.

**Options considered (b chosen):**
- **(a) Broaden the threat model** to include a compromised/delegated user channel. STAC names
  "compromised account, shared agent, or delegated access" — all realistic. Cost: no longer
  strictly like-for-like with Progent, so the comparison framing in D7 needs rewording.
- **(b) Re-home the chains as indirect injection** — keep STAC's *chain structure* but deliver
  the attack through poisoned tool results. Already half-planned as gap #2 in
  `qa-redteam-plan.md`. Cost: the scenarios are then "adapted from STAC", not STAC as
  published, and that must be stated.
- **(c) Report both** as two attacker-capability tiers. Strongest eval chapter; most work;
  highest deadline risk.

**Relevant evidence.** STAC on CaMeL, verbatim: *"control-flow separation defenses such as
CaMeL … isolate a trusted user instruction from untrusted tool-output data, and thus do not
target STAC's vector—in which the adversary acts through the trusted user channel itself."*
A defense built purely for indirect injection does **not** address STAC as published. Whichever
option is chosen, be explicit about which vector the eval actually tests.

---

## D10 — Novelty scope vs. concurrent work (RETIRED as a risk; citation duty remains)
**Decision:** Cite the concurrent work honestly in *Review of Existing Technologies*; make no
novelty claim that depends on it being absent.
**Status:** **Downgraded 2026-08-23.** Two things retired this. First, `spec.md` v2: there is no
rubric line for novelty — this is an industry case study, not a research paper. Second, the
instructor's approval names multi-step sequences as "your real contribution," which settles the
positioning question at the only authority that grades it. ePCA, DSCC, MAGE and ARGUS are
already written into `report/phase1-chapters.md`. **No further reading required.**

*Original entry retained below for the record.*
**Status (original):** **Open risk, raised 2026-08-19.**

STAC's Limitations name a cluster of concurrent agentic guardrails that "report strong
reductions against static attacks", and note that some — **MAGE** explicitly — "evaluate STAC
directly on replays of our released chains":

- [ ] Memory-based — Wang et al. 2026c
- [ ] Provenance-based — Weng et al. 2026
- [ ] Policy-compositional — Schneider et al. 2026
- [ ] Formal-verification — Wu et al. 2026a
- [ ] MAGE — evaluates on STAC replays

STAC also refers to "the cluster of concurrent work that has since independently corroborated"
the compositional mechanism. **None of this is currently in `research.md`, and it is the
biggest live risk to the contribution claim.**

**Action:** resolve each citation from STAC's bibliography, read at least the abstracts, and
narrow the novelty claim deliberately — most likely to *deterministic, inspectable,
policy-as-data* sequence enforcement on a *local open-weight* agent, red-teamed with
deterministic scoring. That is still defensible. Discovering this in a defence session is not.

**Mitigating evidence:** STAC states that whether such guardrails hold "against an adaptive,
execution-validated attacker that re-plans against the installed guardrail … remains
untested." An adaptive-attacker evaluation may be a defensible niche even if the mechanism
is no longer novel.

---

## Blocking now (as of 2026-08-23)
- [ ] **D11** — confirm the process boundary. **Blocks T2.1 / repo layout.** Raised with the
      instructor by email; do not scaffold `src/` until it is settled.
- [ ] **D12** — sequence-state retention. **Blocks T3.1.** Decide from
      `docs/design/open-questions.md` once the design pass produces it.

## Still-open (deferred to the spec, not blocking)
- [ ] Concrete scope-cut order if the end-of-October build deadline slips → defined in
      `tasks/spec.md` Boundaries / scope section.
- [ ] Scenario labelling scheme: ATLAS techniques, Agent-SafetyBench's 10 failure modes, or
      both (see D3).
- [x] ~~D9 threat model~~ → **Resolved 2026-08-23**, option (b), indirect injection.
- [x] ~~D10 novelty scope~~ → **Retired 2026-08-23** as a grading risk; citation duty already
      discharged in `report/phase1-chapters.md`.
- [x] ~~Confirm whether AgentSpec's DSL can express any cross-call condition~~ →
      **Resolved 2026-08-19** (full PDF read). Formally its predicates take the trajectory
      `τ_i`; in practice the defined predicates take current state and action only, and §6.3
      concedes the lack of trajectory-based analysis. Captured in D7.

---

## D11 — Monitor placement / process boundary
**Decision:** The monitor runs as a **separate process**, and the policy engine is the **only**
path to tools. Tools are imported by the monitor process; the agent process holds no import
path to them and reaches them solely through a local decision endpoint.
**Status:** **Proposed / needs Luis's confirmation (raised 2026-08-23).** Blocks T2.1 — this
determines the dispatch layer, so decide before the repo layout is fixed. Raised with Dr.
Alzoubi by email 2026-08-23.

**What raised it.** Instructor feedback, 2026-08-23: *"Say where the monitor sits. If it shares
a process with the agent, the agent can reach it. A separate process with the policy engine as
the only path to tools is safer. Justify your choice."* `spec.md` §4/§6 currently assumes
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
verifiable. Complete mediation is criterion #1 and already test-proven; verifiability comes from
the audit log. Tamperproofness currently has **no test at all**, because in-process there is
nothing to test — the property is asserted, not held. A process boundary converts it into a
structural property with a test behind it.

**Implications to propagate:**
- `spec.md` §4 and §6 — tools move behind the monitor process; the agent gets a thin client.
- **Diagram #8** (deployment / network zones) becomes a real trust boundary rather than
  decoration. It lands in the 25-point Design section, so the decision pays for itself twice.
- **SR-08** (50 ms p95) — loopback IPC adds roughly 1–3 ms, comfortably inside budget, but
  measure it and report the measured figure rather than the assumption.
- **New test:** an import-graph assertion that `src/agent` has no path to `src/tools`. Cheap,
  and it is the direct evidence for the tamperproof claim in the report.
- **Threat model dependency:** AL-2 in `docs/design/threat-model.md` ("adversary cannot read or
  write the policy or monitor state") is a *property* only if this boundary is real. If it
  degrades to in-process, AL-2 becomes an assumption and the report must disclose that.
- **Scope-cut position:** if the boundary threatens the Phase 3 schedule, degrade to in-process
  with the caveat documented — do not lose the sequence engine to it. Insert above item 3 in
  `spec.md` §11.

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
  target destination? The RMM chain smears across sessions if the key is too narrow.
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

**Next step:** the Phase 2 design prompt instructs the coding agent to produce
`docs/design/open-questions.md` laying out the options and what each defeats, without choosing.
Decide from that document.
