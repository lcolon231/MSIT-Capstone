# Research Notes — AI-Agent Containment Monitor Capstone

Working literature file. Feeds the Related Work chapter of the project report and the
citations on the poster. Add sources as they're read; move anything read-and-used into
the "Read" column below.

Companion docs: `Decision Log.md` (decisions + rationale), `docs/project-log/capstone-check-ins.md` (schedule).
PDFs live in `MSIT-Capstone/papers/` on the build box (Paper 1 = Progent, 2 = STAC,
3 = AgentSpec, 4 = GuardAgent).

---

## Positioning statement (use this wording, not the proposal's)

The submitted proposal claimed an independent enforcement layer between agent and tools was
"a genuine, unsolved need." **That claim is wrong and must not appear in the report.**
Progent (2025) and AgentSpec (ICSE 2026) both implement it.

Replacement framing (**revised 2026-08-19 after reading Progent, AgentSpec and STAC in full**):

> Recent work has established action-level runtime enforcement for LLM agent tool calls.
> These systems enforce at discrete execution checkpoints, evaluating the current state and
> the action about to be taken; where they carry state, it is state about the *privilege
> boundary*, not about *behavioral sequence*. AgentSpec's authors state the limitation
> directly: it "lacks support for trajectory-based safety analysis." STAC demonstrates that
> the corresponding attack class succeeds against frontier agents 91.2% of the time. This
> project builds a fail-closed containment monitor with stateful sequence evaluation and
> red-teams it against chained-action escape scenarios, treating false approval as the
> critical metric.

⚠️ **Do not write "these systems evaluate each call in isolation."** Inaccurate about both
papers — Progent's policy updates during execution, and AgentSpec's predicates are formally
defined over the trajectory. Use **checkpoint enforcement vs. trajectory reasoning**
(AgentSpec's own vocabulary) or **privilege state vs. sequence state** (for Progent).

⚠️ **Novelty is now contested — see §2.1 "Concurrent work" below.** STAC's Limitations name
four classes of concurrent agentic guardrail (memory-based, provenance-based,
policy-compositional, formal-verification), and state that one of them, MAGE, "evaluate[s]
STAC directly on replays of our released chains." These must be read and positioned against
before the Related Work chapter is written. This is the single biggest open risk to the
contribution claim.

Contribution is **integration + adversarial evaluation**, not a new mechanism. Claim novelty
only in: (1) the combined feature set, (2) stateful sequence evaluation, (3) local
open-weight agent target, (4) red-team-first methodology.

---

## Read first (priority order)

| # | Source | Why it matters | Read? |
|---|--------|----------------|-------|
| 1 | Progent (arXiv:2504.11703) | Closest prior art. Must differentiate. | ☑ 2026-08-19 (full text) |
| 2 | STAC (arXiv:2509.25624) | The gap + ready-made attack suite. | ☑ 2026-08-19 (full PDF) |
| 3 | AgentSpec (arXiv:2503.18666) | Other prior art. Policy language design. | ☑ 2026-08-19 (full PDF) |
| 4 | AgentDojo (arXiv:2406.13352) | Primary eval harness. Read before experiments. | ☐ |
| 5 | CaMeL (arXiv:2503.18813) | Most rigorous architecture. Aspirational baseline. | ☐ |
| 6 | Zverev et al. (arXiv:2403.06833) | Why instruction-level defense fails. | ☐ |
| 7 | Greshake et al. (arXiv:2302.12173) | Canonical prompt-injection citation. | ☐ |
| 8 | Schneider (2000) + Ligatti et al. (2005) | Formal grounding + honest limits. | ☐ |
| 9 | ToolEmu (arXiv:2309.15817) | Empirical evidence for problem statement. | ☐ |
| 10 | OWASP LLM Top 10 2025 + Agentic AI (2025) | Standards mapping. | ☐ |
| **NEW** | **Concurrent sequence-level guardrails (§2.1)** | **Novelty risk — read before Related Work** | ☐ |
| — | GuardAgent (Paper 4, arXiv:2406.09187) | Rule out LLM-generated guards. | ☐ |

---

## 1. Direct prior art — systems that already do this

### Progent — **the paper to differentiate from** (read 2026-08-19)

**Progent: Securing AI Agents with Privilege Control**
Shi, He, Wang, Li, Wu, Guo & Song (UC Berkeley / UC Santa Barbara / NUS).
arXiv:2504.11703v3, 14 May 2026. <https://arxiv.org/abs/2504.11703>

> ⚠️ Title corrected 2026-08-19. Earlier notes said *"Progent: Programmable Privilege
> Control for LLM Agents"* — that is **not** the paper's title.

**What it does, in three pieces:**

1. **Symbolic rules over tool names *and arguments*.** A rule is not "may send email" but
   closer to "may call `send_email` where recipient matches `@example.com`". Deterministic
   checking at every call; anything with no matching rule is blocked. → Anticipates criteria
   #2 (fail-closed) and #3 (argument awareness) almost exactly.
2. **An LLM *writes* the policy; it never *judges* the call.** Policy author ≠ policy judge.
   → Support for D2's rejection of Python-callable predicates; contrast with GuardAgent.
3. **Monotonic confinement (the SMT-solver part).** Every proposed policy update goes to an
   SMT solver: strictly fewer actions (**narrowing** — automatic) or something new
   (**expansion** — explicit human approval). The action space can only shrink without a
   human. → Cite the *principle*, not the SMT internals.

**Results:** attack success 39.9% → 1.0% on AgentDojo and 70.3% → 3.9% on ASB, utility
maintained. Demonstrated inside LangChain and the OpenAI Agents SDK.

#### The gap citation — verbatim

From **"Progent's Defense Scope"**:

> "Progent cannot be used to defend against attacks that operate within the least privilege
> for accomplishing the user task."

A chain of individually-permitted calls is, by construction, that class. Their illustrating
example is preference-manipulation; the canonical fraud chain is a more severe instance.

Also: "since Progent focuses on constraining tool calls, it does not handle attacks that
target text outputs instead of tool calls."

From **"Attacker Capabilities"** — the threat model:

> "the user is benign, and as such, the user's input query is always benign"

Attackers may manipulate the agent's external data sources, but "cannot modify the agent's
internals, such as training the model or changing its system prompt."

#### ⚠️ Two things Progent does NOT say — do not overclaim

1. Its Discussion never mentions sequential or chained tool calls. Do **not** write "Progent's
   authors acknowledge chained attacks." The limitation *follows from* the stated scope.
   (AgentSpec's concession is the explicit one — lead with that.)
2. It is ambiguous about whether checks consult call history. Do **not** write "Progent is
   memoryless."

---

### AgentSpec — **the policy-language source, and the explicit gap concession** (read 2026-08-19)

**AgentSpec: Customizable Runtime Enforcement for Safe and Reliable LLM Agents**
Haoyu Wang, Christopher M. Poskitt & Jun Sun (Singapore Management University).
ICSE '26, April 12–18 2026, Rio de Janeiro. arXiv:2503.18666.

DSL for runtime constraints, built on LangChain 0.3.13 but framework-agnostic. Domains: code
execution, embodied agents, autonomous driving. Prevents unsafe execution in >90% of
code-agent cases; all hazardous embodied actions; 100% AV legal compliance. Overhead in
**milliseconds** — cite when justifying a deterministic checker on latency grounds.

#### 🎯 The gap citation — verbatim from §6.3 "Limitations and Future Work"

> "AgentSpec currently performs deterministic enforcement at discrete execution checkpoints,
> such as before invoking high-impact API calls or committing irreversible actions. While
> this approach offers high reliability and interpretability, it does not reason about the
> long-term consequences of current actions. Specifically, AgentSpec **lacks support for
> trajectory-based safety analysis**, i.e., estimating whether an action sequence might lead
> to unsafe states several steps into the future."

The closest prior art, at a top-tier SE venue, naming this project's contribution as its own
acknowledged limitation. No interpretation needed. **Lead Related Work with it.**

**Their proposed fix is not this project's.** They suggest *probabilistic* foresight — learn a
Discrete-Time Markov Chain from historical agent interactions, compute probabilistic
reachability. This project (D1) uses a **deterministic kill-chain automaton**. Argue the
difference: a probabilistic verdict reintroduces the non-determinism the monitor exists to
remove, is not inspectable as version-controlled policy, and would breach the rule that no
probabilistic component sits in a success metric.

#### The formalism — read carefully before claiming anything about state

**Definition 3.1:** a rule is `r = (η_r, P_r, E_r)` — triggering event, predicate set, and a
*sequence* of enforcement functions. Given trajectory
`τ_i = ⟨s₀ →a₀ s₁ →a₁ … →a_{i-1} s_i⟩`, three general triggers: **state change**, **action**
(fires pre-execution), **agent_finish**. Each predicate is `p_r(u, τ_i) ∈ B` — **formally it
takes the whole trajectory**. But:

> "The inputs to these predicate functions depend on the type of trigger event. For a state
> change event, the predicate function requires only the current state 𝑠𝑖. For an action
> event, the predicate function requires both the current state 𝑠𝑖 and the action 𝑎𝑖."

⚠️ Do **not** write "AgentSpec cannot express cross-call conditions" — Definition 3.1 says
otherwise. Write that enforcement is *evaluated at discrete checkpoints over current state
and action*, and quote §6.3. The concession does the work.

#### Triggers, checks, enforcements — the structure D2 borrows

```
rule @inspect_transfer
trigger Transfer
check
    !is_to_family_member
enforce
    user_inspection
end
```

Predicates are named, declarative, domain-scoped functions — `is_destructive_cmd`,
`is_fragile_object`, `obstacle_distance_leq(n)`, `!has_access(role, resource)`,
`!is_sensitive(text)`. §6.2: enforcement "is declarative and externalized from the LLM,
ensuring consistent behavior across runs, environments, and model versions." → **D2's
justification, peer-reviewed.**

General enforcement actions (§3.2): `user_inspection`, `llm_self_examine`, `invoke_action`,
plus domain-specific ones (`stop`, `follow_dist(10)` …). The intro summarises the family as
"action termination, user inspection, corrective invocation, and self-reflection."

| AgentSpec | This project |
|---|---|
| `trigger` (action event, pre-execution) | tool-call interception — same placement |
| `check` predicate | argument-aware matcher (criterion #3) |
| action termination / `stop` | `DENY` |
| `user_inspection` | `GATE` (D5) |
| `llm_self_examine` | **not implemented — see D8** |
| `invoke_action` (corrective) | **not implemented — see D8** |

#### Other useful findings

- **LLM-generated rules:** precision 95.56%, **recall 70.96%** (also 87.26% of risky code;
  AV law-breaking prevented in 5 of 8). ~29% of unsafe cases missed → argument for
  hand-authored policy. Pair with GuardAgent.
- **§6.1** is a ready-made Related Work skeleton: NeMo constrains at the *dialogue* level;
  llama.cpp and LCEL do *syntactic* pattern-matching; GuardAgent relies on *LLMs* to interpret
  constraints; AgentSpec uses "an external, developer-defined enforcement model" whose
  "explicit separation between the agent's reasoning and its safety enforcement mechanism
  improves verifiability and robustness." **That is this project's independence claim, already
  peer-reviewed — quote it.**
- **Table 3:** an unconstrained LangChain code agent attempted the risky action in **24 of 25
  risky categories** (reverse shells, path traversal, eval injection, posting sensitive files
  online). Good problem-statement evidence.
- The worked example gates a **financial transfer** on a recipient predicate via human
  inspection — near-identical to this project's RMM export domain. Precedent for D5.

---

## 2. The gap — multi-step / chained actions

**The three-citation argument for Related Work, in order:**
1. **AgentSpec §6.3** — "lacks support for trajectory-based safety analysis" (explicit
   concession, ICSE 2026).
2. **Progent, Defense Scope** — cannot defend against attacks "that operate within the least
   privilege for accomplishing the user task."
3. **STAC** — that attack class succeeds **91.2%** of the time across 483 verified cases.

Prior art concedes the gap; the benchmark shows it is exploited at scale; this project builds
and red-teams the mechanism.

### STAC — the gap evidence and the scenario source (read 2026-08-19, full PDF)

**STAC: When Innocent Tools Form Dangerous Chains for LLM Agents**
Jing-Jing Li (UC Berkeley, work done during an AWS AI Labs internship), Jianfeng He, Chao
Shang, Devang Kulshreshtha, Xun Xian, Yi Zhang, Hang Su, Sandesh Swamy, Yanjun Qi
(**AWS AI Labs**). arXiv:2509.25624v3, 19 Jul 2026.
**Data and code: <https://github.com/amazon-science/MultiTurnAgentAttack>**

> ⚠️ Title corrected 2026-08-19. Earlier notes said "…Dangerous Chains **to Jailbreak** LLM
> Agents". The correct title uses "**for** LLM Agents".

**Sequential Tool Attack Chaining**: chains of tool calls each harmless in isolation that
collectively enable harm, apparent only at the final execution step. An automated closed-loop
pipeline synthesises executable multi-step chains, validates them by in-environment
execution, and reverse-engineers stealthy multi-turn prompts that induce the agent to execute
the verified sequence. 483 cases, 1,352 user–agent–environment interaction sets, 10
agent-specific failure modes (from Agent-SafetyBench / Zhang et al. 2024).

**Results:** mean final **ASR 91.2%** across 8 agents in 4 families (open-weight and frontier,
incl. GPT-4.1); >90% for all but one. Single-turn ablation (final request without the
synthesised prefix) drops to **72.8% vs 95.1%** for full STAC — quantifying that distributing
intent across benign-looking verified steps is what defeats the defenses.

**The thesis quote — use it in the introduction:**

> "These results highlight a crucial gap: defending tool-enabled agents requires reasoning
> over entire action sequences and their cumulative effects, rather than evaluating isolated
> prompts or responses."

And from §3: agent vulnerability traces to "their reliance on step-by-step tool execution
without holistic sequence reasoning about the cumulative consequences of multi-turn
interactions."

#### 🚨 THREAT-MODEL MISMATCH — resolve before building scenarios (D3 / D9)

STAC's §2.1 Threat Model, verbatim:

> "The adversary issues prompts directly through the user-facing interface (e.g., via a
> compromised account, shared agent, or delegated access). We evaluate this direct-access
> setting and leave indirect prompt injection to future work."

**This is incompatible with the threat model currently adopted from Progent** (benign user,
benign query, attacker controls only external data). STAC's adversary *is* the user channel.
D3 plans to adapt STAC chains into the red-team suite — that cannot be done without
reconciling the two. Options, tracked as **D9** in the Decision Log:

- **(a) Broaden the threat model** to include a compromised/delegated user channel. STAC
  explicitly names "compromised account, shared agent, or delegated access" — all realistic.
  Cost: no longer strictly like-for-like with Progent.
- **(b) Re-home the chains as indirect injection** — keep STAC's *chain structure* but deliver
  the attack through poisoned tool results. Already half-planned as gap #2 in
  `qa-redteam-plan.md`. Cost: the chains are no longer STAC's as published, so cite as
  "adapted from".
- **(c) Report both** as two attacker-capability tiers. Strongest eval; most work.

**Relevant to the choice** — STAC on CaMeL, verbatim from their Limitations:

> "control-flow separation defenses such as CaMeL … isolate a trusted user instruction from
> untrusted tool-output data, and thus do not target STAC's vector—in which the adversary acts
> through the trusted user channel itself—although their policy-enforcement layer (e.g.,
> confirmation for sensitive actions) is complementary to the action-level defenses we
> advocate."

Note what this implies: a defense built purely for indirect injection does **not** address
STAC. If option (b) is chosen, be explicit that the project is testing an *adapted* threat
vector, not STAC as published.

#### 🎯 STAC names this project's design as important future work

From their **Limitations → Defense scope**, verbatim:

> "Our stealth metrics (PH, RR) likewise do not test **sequence-level monitors such as
> audit-log, action-pattern, or state-diff analysis**."

and

> "…as well as **action-level policies such as user confirmation for destructive actions**,
> could provide stronger protection and are important future directions."

That is (i) the D1 sequence engine and (ii) the D5 approval gate, named by the benchmark's own
authors as untested and important. **Cite both sentences in the report's motivation.**

#### Defenses evaluated (all prompt-based — the baseline to beat)

Their defense study is "deliberately scoped to prompt-based defenses, which deploy without
model retraining or re-architecting the agent": Spotlighting via Datamarking (Hines et al.),
Failure Modes (Zhang et al.), Summarization, their own **Reasoning** defense (harm–benefit
analysis over the full conversation history before each tool call), and **ToolShield** (Li et
al. 2026a), an experience-based defense that learns from prior attack trajectories.

Headline: no prompt-based defense is sufficient. Reasoning gives the largest first-turn
reduction (**ASR 87.4% → 58.6%**) but erodes under adaptation; **ToolShield is most durable at
T+2 (78.1%)**. Under a defense-aware Planner given the exact installed defense prompt, every
prompt-based defense erodes — and notably the Planner then has to abandon the sequence-level
exploit itself, which the authors read as confirming "STAC's effectiveness comes from
sequence-level context rather than prompt-level engineering."

→ **This is the comparison baseline for the report.** Prompt-based defenses top out around
58.6% ASR at best and erode; a deterministic sequence monitor is a different mechanism class
entirely. Do not claim a numeric comparison against these figures without matching the setup.

#### Metrics (align criterion #6 vocabulary with theirs)

- **ASR** — Attack Success Rate (proportion of cases where the attack succeeded).
- **PH** — Prompt Harmfulness.
- **RR** — Refusal Rate.

Reported per turn (T, T+1, T+2), showing ASR climbing across turns. This project's
false-approval maps to ASR and false-block maps to a benign-case analogue of RR; state the
mapping explicitly rather than inventing new names.

#### Environments — directly reusable

4 complex environments from **SHADE-Arena** (Kutasov et al. 2025), which *extends AgentDojo*:
**RMM**, Travel, Workspace, Spam Filter Updating — plus 62 simpler ones sampled from
Agent-SafetyBench. All implemented in Python with distinct tool sets. Also a real-tool MCP
benchmark (filesystem + Playwright servers, OpenAgentSafety tasks) where the attacker is
black-box: full pipeline **35.5% ASR vs 12.5%** without pre-generated chains.

→ Their **RMM** environment and the released chains are the closest available match to
this project's canonical fraud chain. Check the repo before authoring scenarios from scratch
(D3, Task 14). ⚠️ **Corrected 2026-09-14 — this premise does not hold against the actual
release: the published repo contains *no* RMM task pair. See *STAC repository review* below.**

#### STAC repository review (issue #18 / Task 14) — completed 2026-09-14

Direct inspection of the **published** repo <https://github.com/amazon-science/MultiTurnAgentAttack>,
the diligence step T5.2 required before treating the suite as final.

**What is actually released:**
- `data/STAC_benchmark_data.json` — 483 cases as JSON. Each record carries `id`,
  `generation_config.dataset`, `generation_config.environment`, `attack_plan`
  (goal, explanation, `verified_tool_chain`), and `interaction_history` (the transcript).
- `SHADE_Arena/task_pairs/` — the released SHADE-Arena environments are exactly five:
  **`american_airlines_2`, `api_key_calendar_agendas_2`, `bank_transfer_2`,
  `expenditure_accounting`, `spam_filter_update`** — plus the Agent-SafetyBench simpler set.
- License: **CC BY-NC 4.0 (non-commercial)** — the framework is NC even though its underlying
  SHADE-Arena / Agent-SafetyBench data are MIT.

**Finding — no reusable RMM chain exists in the release.** The paper names an RMM environment,
but it is **not among the published task pairs** (corrected above). The nearest structural
analogues to this project's chains are:
- `bank_transfer_2` / `expenditure_accounting` → financial *exfiltration* structure, structurally
  parallel to our `export_records` recon→register→export chain;
- `api_key_calendar_agendas_2` → credential access, parallel to our `credential_theft` scenario.

None is drop-in reusable: they carry no RMM/PHI/healthcare-MSP surface, and — per **D9** — STAC's
direct-user-channel threat model is re-homed here as indirect injection, so even the closest
chains would require full re-authoring. Two independent reasons therefore stand against verbatim
import: (i) there are no RMM chains to import, and (ii) CC BY-NC 4.0 would encumber reuse in this
work regardless.

**Decision:** keep the suite's scenarios as **original constructions whose chain *structure* is
STAC-informed and cited "adapted from"** (`src/eval/suite.py`). The 6-attack / 4-benign suite is
sufficient as-is; no scenario is added or swapped on the strength of this review (the suite scale
is deliberately capped — spec §11). Task 14 / issue #18 is closed.

#### STAC's own limitations — two of them help this project

- **LLM judge:** attack success is scored by a **GPT-4.1 Judge sharing a model family with the
  Generator and Planner**. They concede "a single-family judge may shape the reported ASR, PH,
  and RR" and call cross-family judging and human validation important next steps.
  → **Direct justification for D6.** This project's per-scenario deterministic checkers avoid
  precisely this. Cite their concession when defending the design.
- **Single-run point estimates:** no variance characterised; "small gaps between defenses …
  should be read with caution." → A modest, achievable methodological improvement: report
  multi-seed runs.
- **Selection bias:** the benchmark contains only chains that passed in-environment
  verification, so reported ASR is conditional on a verifiable chain.
- **Predefined failure modes** may limit discovery of novel patterns.

### 2.1 ⚠️ Concurrent work — READ BEFORE WRITING RELATED WORK (novelty risk)

STAC's Limitations name a cluster of concurrent agentic guardrails that "report strong
reductions against static attacks", and note that **some (e.g. MAGE) evaluate STAC directly on
replays of the released chains**:

- [ ] **Memory-based** — Wang et al. 2026c
- [ ] **Provenance-based** — Weng et al. 2026
- [ ] **Policy-compositional** — Schneider et al. 2026
- [ ] **Formal-verification** — Wu et al. 2026a
- [ ] **MAGE** — evaluates on STAC replays

STAC also refers to "the cluster of concurrent work that has since independently corroborated"
the compositional mechanism. **This is the biggest live risk to the novelty claim** and none of
it is currently in this file. Resolve each citation from STAC's bibliography, read at least
the abstracts, and position against them explicitly. It may narrow the claim (e.g. to
*deterministic, inspectable, policy-as-data* sequence enforcement on a *local open-weight*
agent) — which is still defensible, but the claim must be narrowed deliberately rather than
discovered by a reviewer.

Encouragingly, STAC also says whether such guardrails hold "against an adaptive,
execution-validated attacker that re-plans against the installed guardrail … remains
untested."

**ChainWatch** — arXiv:2607.19432. <https://arxiv.org/html/2607.19432>
Kill-chain-aligned stateful detection for MCP agents. Names the canonical fraud chain:
`list_endpoints → list_shares → register_destination → export_records`. Per-call defenses pass all five;
sequence-level rules flag it.
→ *Method to borrow for the stateful policy; clearest worked example for the report.*

**SafeFlow** — arXiv:2607.25255. Locally-benign-globally-malicious as an information-flow
problem. *Alternative approach; mention, don't implement.*

---

## 3. Classical foundations (reviewers will expect these)

- **Anderson (1972)**, *Computer Security Technology Planning Study*, ESD-TR-73-51 — the
  reference monitor: complete mediation, tamperproof, verifiable.
- **Saltzer & Schroeder (1975)**, *The Protection of Information in Computer Systems*, Proc. IEEE
  — least privilege, fail-safe defaults, complete mediation, economy of mechanism.
  → Progent explicitly frames itself as least privilege for tool calls; cite together.
- **Schneider (2000)**, *Enforceable Security Policies*, ACM TISSEC — security automata; which
  policies an execution monitor can enforce (safety, not liveness).
  → Theoretical basis **and** the honest limitation: no completeness guarantee for sequence
  detection. Pairs with AgentSpec's probabilistic-reachability proposal to frame D1's limits.
- **Ligatti, Bauer & Walker (2005)**, *Edit automata*, IJIS —
  <https://link.springer.com/article/10.1007/s10207-004-0046-8> — monitors that suppress,
  insert, or terminate actions. → The frame for D8's suppression-only subset.
- **seccomp-BPF / AppArmor / SELinux / gVisor** — the OS analogue. "seccomp for tool calls".
- **Capability-based security** — Dennis & Van Horn (1966); Miller, Yee & Shapiro,
  *Capability Myths Demolished*.

---

## 4. Threat model — prompt injection

⚠️ **Unresolved:** Progent's model (benign user) and STAC's model (adversary on the user
channel) are different, and this project currently intends to borrow from both. See the
THREAT-MODEL MISMATCH box in §2 and D9 in the Decision Log. Settle before Task 14.

- **Greshake et al. (2023)**, *Not what you've signed up for*, ACM AISec '23, arXiv:2302.12173
  — founds indirect prompt injection. Canonical.
- **Zverev et al. (ICLR 2025)**, *Can LLMs Separate Instructions from Data?*, arXiv:2403.06833
  — all tested models fail to achieve high separation; canonical mitigations either don't help
  or cost utility. → **Why enforcement must live outside the model.** Backbone of the problem
  statement.
- **Willison (2023)**, *The Dual LLM pattern*. <https://simonwillison.net/2023/Apr/25/dual-llm-pattern/>
- **Microsoft MSRC (2025)** — "assume indirect prompt injection is inevitable and design
  systems to contain it." Industry validation of the containment framing.
- **Adaptive Attacks Break Defenses Against IPI** — arXiv:2503.00061. Motivates red-team-first
  evaluation and the false-approval metric. Reinforced by STAC's defense-aware Planner result.

---

## 5. Human approval gates / irreversibility

- **Turan (2026)**, *Oversight Has a Capacity*, arXiv:2606.08919 — reviewer as fatiguing, not
  an infinite oracle. Informs gate design and alert-fatigue risk.
- **Mind the Web** — arXiv:2506.07153. HITL confirmation before irreversible actions.
- Scope approval to **irreversibility × blast radius**. Rubber-stamping is worse than no gate.
- *Cross-reference:* Progent gates *policy expansions* rather than individual actions — a
  useful contrast for D5.
- *Cross-reference:* AgentSpec's `user_inspection` is the direct analogue of `GATE`, and its
  worked example gates a **financial transfer** on a recipient predicate.
- *Cross-reference:* **STAC explicitly names "action-level policies such as user confirmation
  for destructive actions" as an important future direction** — the benchmark's authors
  endorsing the D5 design. Strongest available motivation citation for the gate.

---

## 6. Evaluation — reuse, don't rebuild

| Benchmark | Scale | What it gives | Use |
|---|---|---|---|
| **AgentDojo** (arXiv:2406.13352, NeurIPS 2024) | 97 tasks, 900+ pairs, 4 domains | Deterministic state-based checks; ASR + utility + utility-under-attack | **Primary harness.** In UK AISI Inspect. |
| **STAC** (arXiv:2509.25624) | 483 chained cases, 1,352 interaction sets | Multi-step escape scenarios + released chains | **Primary for the sequence claim.** Repo: amazon-science/MultiTurnAgentAttack |
| **SHADE-Arena** (Kutasov et al. 2025) | 4 complex envs, extends AgentDojo | RMM / Travel / Workspace / Spam Filter | STAC's main environments — check before authoring scenarios |
| **Agent-SafetyBench** (Zhang et al. 2024) | 62 sampled envs; 10 failure modes | Failure-mode taxonomy | STAC's labelling scheme; alternative to ATLAS labels |
| **InjecAgent** (arXiv:2403.02691) | 1,054 cases | IPI-specific | Secondary. |
| **Agent Security Bench** (arXiv:2410.02644) | 10 scenarios, 400+ tools | 27 attack/defense methods | Secondary; Progent used it. |
| **AgentHarm** (arXiv:2410.09024) | 110 / 440 tasks | Capability retention under jailbreak | Optional. |
| **ToolEmu** (arXiv:2309.15817) | 36 toolkits, 144 cases | LM-emulated sandbox + auto evaluator | Evidence + method. |

**Metrics — report all three or the eval is not credible:**
- False approval / attack success rate (**ASR**, STAC's term) — the critical metric. ✔
- False block / benign-refusal rate — **a monitor that blocks everything gets 0% ASR.**
  (STAC's **RR** is the closest published analogue.)
- Task utility and utility-under-attack.

Report ASR **per domain and per attack**. AgentDojo's undefended ASR varies sharply
(Slack ~58%, RMM ~19%, Workspace ~0% in one replication) — a single headline number is
misleading. Progent reports AgentDojo *and* ASB with utility alongside ASR. STAC reports per
turn (T, T+1, T+2) — worth mirroring, since ASR climbing across turns is itself the sequence
evidence.

**Methodological improvements this project can honestly claim over STAC:** deterministic
per-scenario checkers instead of a single-family LLM judge (D6 — STAC concedes this
limitation), and multi-seed runs instead of single-run point estimates (STAC concedes this
too). The multi-seed claim is now backed by evidence rather than intent: the ten-scenario
suite was run at **n=5 seeds** against a live `llama3.1:8b` (2026-09-04), and the four legacy
rates held at 100 / 0 / 0 / 100 on every seed with attempt rate 3/6 and monitor containment 3/3
(sample SD 0.0% on all six metrics). The spread is nonetheless *not* zero where it matters:
**which** attacks the model attempts varies by seed — `attack.exfil_interleaved` was attempted
on 4 of 5 seeds and `attack.indirect_injection_exfil` on 1 of 5 — so a stable aggregate hides
per-scenario churn, which is precisely the failure mode a single-run point estimate cannot
expose. Two caveats bound the claim: n=5 on one 8B model is a small sample and no seed produced
an escape, so these are zero-variance-in-the-tail numbers rather than a fitted distribution; and
multi-seed sampling only works with an explicit non-zero temperature, because the packaged model
decodes greedily at `temperature 0` and returns identical output for every seed. See
`docs/evaluation-results.md` § *Multi-seed live run (n=5)*.

---

## 7. Standards mapping (corrected)

- **NIST CSF 2.0** — CSWP 29, Feb 2024. <https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf>
  Say **2.0**. Protect (access control, least privilege) + Detect (audit log, blocked-attempt
  monitoring). Consider Govern for policy ownership.
- **NIST AI RMF 1.0 (2023) + Generative AI Profile (AI 600-1, July 2024)** — Govern/Map/
  Measure/Manage. Red-teaming maps to Measure and Manage.
- **OWASP Top 10 for LLM Applications 2025** — **LLM01 Prompt Injection**, **LLM06 Excessive
  Agency**. ⚠️ Insecure Plugin Design folded into LLM06 + Supply Chain. Don't cite the 2023 list.
- **OWASP Agentic AI Threats and Mitigations (2025)** —
  <https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/>

---

## 8. Evidence for the problem statement

- **STAC** — mean final **ASR 91.2%** across 8 agents; >90% for 7 of 8. The strongest single
  number available for "agents chain innocent tools into harm."
- **ToolEmu** — even the safest agent showed risky failures **23.9%** of the time; 68.8% of
  identified failures judged valid real-world failures.
- **AgentDojo** — undefended GPT-4o hijacked at **53.10%** targeted attack success.
- **AgentSpec Table 3** — an unconstrained LangChain code agent attempted the risky action in
  **24 of 25 risky categories** (reverse shells, path traversal, eval injection, exfiltration).
- **SandboxEscapeBench** (arXiv:2603.02277) — LLMs can exploit container sandbox escapes.
- **Fang et al.** (arXiv:2404.08144) — GPT-4 exploited 87% of 15 one-day vulnerabilities given
  the CVE description; 7% without.
- **ClawsBench** (arXiv:2604.05172) — sandbox-escalation behavior across all tested models.

⚠️ **Do not cite** the circulating vendor-blog / Substack accounts of a 2026 "autonomous agent
breached production infrastructure" incident. Not primary-sourced. Unverified.
*(Note: STAC §2.1 cites Anthropic's published analysis of real-world AI-enabled espionage as
corroboration of the threat pattern — that is a primary source and may be citable. Track down
the actual Anthropic publication from STAC's bibliography before using it.)*

---

## Open questions to resolve before the build

- [ ] **Threat model: reconcile Progent's benign-user model with STAC's user-channel
      adversary** — options (a)/(b)/(c) in §2, tracked as D9. Blocks Task 14. **Highest priority.**
- [ ] **Read the concurrent sequence-level guardrails in §2.1** (esp. MAGE) and narrow the
      novelty claim deliberately — tracked as D10. **Blocks Related Work.**
- [ ] Check the STAC repo (amazon-science/MultiTurnAgentAttack) for reusable RMM chains
      before authoring scenarios from scratch.
- [ ] Scenario labelling: ATLAS techniques (per `qa-redteam-plan.md`) or Agent-SafetyBench's
      10 failure modes, or both?
- [ ] Which local open-weight model drives the agent? (→ D4, settled)
- [ ] How is "escape" scored in the red-team suite? (→ D6, settled; strengthened by STAC's
      LLM-judge concession)
- [ ] Scope cuts if the end-of-October build deadline slips.
