# Research Notes — AI-Agent Containment Monitor Capstone

Working literature file. Feeds the Related Work chapter of the project report and the
citations on the poster. Add sources as they're read; move anything read-and-used into
the "Read" column below.

Companion doc: `Decision Log.md` (decisions + rationale). The project report's source is not
kept in this public repository; "the report" below means the report chapters as drafted.
PDFs live in `MSIT-Capstone/papers/` on the build box (Paper 1 = Progent, 2 = STAC,
3 = AgentSpec, 4 = GuardAgent).

> **Status as of 2026-10-28.** Build and evaluation are complete and tagged `v1.0-capstone`.
> The open research questions below are resolved by D4, D6, D9, D10 and D13 and the STAC repo
> review; resolutions are marked in place and summarised under
> [*Open questions*](#open-questions--status-2026-10-28). The final evaluation result is under
> §6, the sources cited on the poster and executive summary are under §9, and what still
> needs checking before the final report is in the open-questions list.

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

✅ **Novelty risk resolved (D10, confirmed 2026-08-23).** STAC's Limitations name four classes
of concurrent agentic guardrail (memory-based, provenance-based, policy-compositional,
formal-verification), one of which, MAGE, "evaluate[s] STAC directly on replays of our
released chains." All four are identified in §2.1 and positioned against in the report
(*Review of Existing Technologies*). The claim was narrowed
deliberately to **deterministic, inspectable, policy-as-data sequence enforcement on a local
open-weight agent, red-teamed with deterministic per-scenario scoring**; the compositional
mechanism itself is **not** claimed as novel.

Contribution is **integration + adversarial evaluation**, not a new mechanism. Claim novelty
only in: (1) the combined feature set, (2) stateful sequence evaluation, (3) local
open-weight agent target, (4) red-team-first methodology.

⚠️ **Do not claim the adaptive-attacker niche as evaluated.** D10 names "an adaptive,
execution-validated attacker that re-plans against the installed guardrail" as the niche STAC
flags as untested, and the report's review conclusion leans on it. The evaluation as run used
fixed scenarios driven by a scripted agent and by a live `llama3.1:8b`; no attacker re-planned
against the installed monitor. State the adaptive attacker as future work, not as a result.

---

## Read first (priority order)

"Read?" records only what was logged at the time; tick anything read since. "Cited in report?"
is from a search of the report chapters' markdown source on 2026-10-28.

| # | Source | Why it matters | Read? | Cited in report? |
|---|--------|----------------|-------|---|
| 1 | Progent (arXiv:2504.11703) | Closest prior art. Must differentiate. | ☑ 2026-08-19 (full text) | ✔ |
| 2 | STAC (arXiv:2509.25624) | The gap + ready-made attack suite. | ☑ 2026-08-19 (full PDF) | ✔ |
| 3 | AgentSpec (arXiv:2503.18666) | Other prior art. Policy language design. | ☑ 2026-08-19 (full PDF) | ✔ |
| 4 | AgentDojo (arXiv:2406.13352) | Benchmark; integration deferred to future work (D3). | ☐ | ✔ |
| 5 | CaMeL (arXiv:2503.18813) | Most rigorous architecture. Aspirational baseline. | ☐ | ✔ |
| 6 | Zverev et al. (arXiv:2403.06833) | Why instruction-level defense fails. | ☐ | ✔ |
| 7 | Greshake et al. (arXiv:2302.12173) | Canonical prompt-injection citation. | ☐ | ✗ |
| 8 | Schneider (2000) + Ligatti et al. (2005) | Formal grounding + honest limits. | ☐ | Schneider ✔ · Ligatti ✗ |
| 9 | ToolEmu (arXiv:2309.15817) | Empirical evidence for problem statement. | ☐ | ✗ |
| 10 | OWASP LLM Top 10 2025 + Agentic AI (2025) | Standards mapping. | ☐ | ✔ (both) |
| — | Concurrent sequence-level guardrails (§2.1) | Novelty risk — resolved by D10 | identified; see §2.1 | ✔ (MAGE, ARGUS, DSCC, ePCA) |
| — | GuardAgent (Paper 4, arXiv:2406.09187) | Rule out LLM-generated guards. | ☐ | ✔ |

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

#### Threat-model mismatch (D3 / D9) — ✅ resolved 2026-08-23: option (b)

> **Resolution (D9).** The project adopts **indirect prompt injection**: the operator is a
> trusted Provider technician with a benign task, and the adversary plants content in data the
> agent ingests (ticket bodies, email, log lines, filenames, tool results). A compromised or
> malicious operator is out of scope. STAC's chain *structure* is re-homed as indirect
> injection, so the suite's scenarios are cited **"adapted from STAC"**, never as STAC as
> published. The deliberation below is kept for provenance.

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
**Banking**, Travel, Workspace, Spam Filter Updating — plus 62 simpler ones sampled from
Agent-SafetyBench. All implemented in Python with distinct tool sets. Also a real-tool MCP
benchmark (filesystem + Playwright servers, OpenAgentSafety tasks) where the attacker is
black-box: full pipeline **35.5% ASR vs 12.5%** without pre-generated chains.

→ Their **Banking** environment and the released chains were the closest available match to
this project's original (banking) kill chain. Check the repo before authoring scenarios from
scratch (D3, Task 14). → **Checked 2026-09-14: Banking is released as `bank_transfer_2`, but
nothing in STAC has an RMM/PHI surface, so no chain is reusable for the RMM domain (D18). See
*STAC repository review* below.**

> ⚠️ **Corrected 2026-10-28.** From 2026-08-29 to 2026-10-28 this file named STAC's, SHADE-Arena's
> and AgentDojo's *Banking* environment "RMM". The D18 domain rename (commit `89bec06`) was
> applied to the literature descriptions as well as to the project's own domain. Neither
> benchmark has an RMM environment; "RMM" in this file now refers only to this project.

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

**Finding — no reusable RMM chain exists in the release.** STAC has no RMM environment at all;
its Banking environment *is* released (`bank_transfer_2`), but no task pair has an RMM, PHI or
healthcare-MSP surface (wording corrected 2026-10-28, see the note above). The nearest
structural analogues to this project's chains are:
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

### 2.1 Concurrent work — ✅ identified and positioned (D10, novelty scope narrowed)

STAC's Limitations name a cluster of concurrent agentic guardrails that "report strong
reductions against static attacks", and note that **some (e.g. MAGE) evaluate STAC directly on
replays of the released chains**. Each class is now identified and positioned against in the
report (*Review of Existing Technologies*). Positioning, as the
report states it:

| STAC's class | Paper (as cited in the report) | Positioning |
|---|---|---|
| Memory-based (Wang et al. 2026c) | **MAGE** (Wang et al., 2026): safety-focused shadow memory across the trajectory; evaluates on STAC replays | Puts a probabilistic (LLM) component inside the enforcement path |
| Provenance-based (Weng et al. 2026) | **ARGUS** (Weng et al., 2026): audits causal provenance from evidence to action | Rigorous, but requires re-architecting the agent |
| Policy-compositional (Schneider et al. 2026) | **DSCC** (Schneider et al., Microsoft AI, 2026): composes per-tool policies into a chain-level policy under a monotonicity invariant, with taint tracking | Deterministic sequence enforcement is achievable; reports policy-blocking rates but **no adversarial evaluation** |
| Formal-verification (Wu et al. 2026a) | **ePCA** (Wu et al., 2026): agent formalises its intent in first-order logic, verified by an SMT solver | Depends on the agent declaring its own intent; this monitor stays independent of the agent |

STAC also refers to "the cluster of concurrent work that has since independently corroborated"
the compositional mechanism. **Consequence (D10):** the compositional mechanism is not claimed as
novel. The claim is narrowed to *deterministic, inspectable, policy-as-data* sequence
enforcement on a *local open-weight* agent, red-teamed with deterministic per-scenario scoring
and reported on the false-approval / false-block / utility trade-off.

How deeply each paper was read is not recorded here. Before the final report, confirm the
report's one-line characterisation of each against at least its abstract, and add full APA
entries; the four citations appear only in the body text of the report's markdown source, which has no
reference list yet.

Encouragingly, STAC also says whether such guardrails hold "against an adaptive,
execution-validated attacker that re-plans against the installed guardrail … remains
untested."
⚠️ This project did **not** evaluate such an attacker either (see the warning under
*Positioning statement*). It remains an open niche and belongs under future work.

**ChainWatch** — arXiv:2607.19432. <https://arxiv.org/html/2607.19432>
Kill-chain-aligned stateful detection for MCP agents. Names the canonical fraud chain:
`get_balance → list_payees → add_payee → transfer_funds`. Per-call defenses pass all five;
sequence-level rules flag it. (This project's RMM counterpart, after D18:
`list_endpoints → list_shares → register_destination → export_records`. The tool names above are
ChainWatch's own; they were wrongly replaced by the D18 rename from 2026-08-29 to 2026-10-28.)
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

✅ **Resolved by D9 (2026-08-23): indirect prompt injection.** Progent's model (benign user)
and STAC's model (adversary on the user channel) differed; the project adopts Progent's: a
trusted operator with a benign task, and an external adversary who plants instructions in
ingested content and tool results. STAC's chains are re-homed as indirect injection and cited
"adapted from". See the threat-model box in §2.

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

What was actually used (D3, D13, STAC repo review): a **custom 6-attack / 4-benign suite** whose
chain structure is adapted from STAC, scored by deterministic per-scenario checkers (D6) and
labelled with one MITRE ATLAS technique per scenario (D13). The "Use" column below was the
August plan; the outcome is noted in brackets.

| Benchmark | Scale | What it gives | Use |
|---|---|---|---|
| **AgentDojo** (arXiv:2406.13352, NeurIPS 2024) | 97 tasks, 900+ pairs, 4 domains | Deterministic state-based checks; ASR + utility + utility-under-attack | Planned as primary harness. [Not integrated; stretch goal under D3, now future work. Its state-based checking is the model for D6.] In UK AISI Inspect. |
| **STAC** (arXiv:2509.25624) | 483 chained cases, 1,352 interaction sets | Multi-step escape scenarios + released chains | **Primary for the sequence claim.** [Chain structure adapted; no chains imported (repo review 2026-09-14).] Repo: amazon-science/MultiTurnAgentAttack |
| **SHADE-Arena** (Kutasov et al. 2025) | 4 complex envs, extends AgentDojo | Banking / Travel / Workspace / Spam Filter | STAC's main environments. [Checked; no RMM surface.] |
| **Agent-SafetyBench** (Zhang et al. 2024) | 62 sampled envs; 10 failure modes | Failure-mode taxonomy | STAC's labelling scheme. [Optional secondary tag only; ATLAS is primary (D13).] |
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
(Slack ~58%, Banking ~19%, Workspace ~0% in one replication) — a single headline number is
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

**Final result as reported (poster, executive summary, README).** Containment is reported two
ways (D20), leading with the attempt-gated figure:

| Measure (n=5, `llama3.1:8b`, temperature 0.8) | Result |
|---|---|
| Attack runs whose harmful action reached the monitor | 15 of 30 |
| Attempted attacks contained | 15 of 15: 5 by automatic DENY, 10 by GATE timeout |
| Escapes (false approval) | 0 of 30 |
| Benign tasks completed / wrongly blocked | 20 of 20 / 0 of 20 |
| Approval prompts on benign tasks | 30 over 20 tasks, ≈ 1.5 per task |
| Sequence-engine DENY | 3 of 3 scripted exfiltration chains; 0 in live runs |

- **Never lead with the legacy 100% containment rate**; it counts the 15 unattempted runs as
  contained.
- **Do not set "0 escapes" against STAC's 91.2% ASR** as if it were a measured reduction. The
  threat model (D9), attacker, agent model and scoring all differ (see the STAC defenses
  subsection: "Do not claim a numeric comparison … without matching the setup").
- **Both methodological improvements over STAC are delivered**: deterministic scoring (D6) and
  multi-seed runs with variance reported. What is **not** demonstrated is live multi-step chain
  detection: the live model never produced the full chain.

---

## 7. Standards mapping (corrected)

- **NIST CSF 2.0** — CSWP 29, Feb 2024. <https://doi.org/10.6028/NIST.CSWP.29> (DOI verified
  2026-10-27; PDF: <https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf>)
  Say **2.0**. Protect (access control, least privilege) + Detect (audit log, blocked-attempt
  monitoring). Consider Govern for policy ownership.
- **NIST AI RMF 1.0 (2023) + Generative AI Profile (AI 600-1, July 2024)** — Govern/Map/
  Measure/Manage. Red-teaming maps to Measure and Manage.
- **OWASP Top 10 for LLM Applications 2025** — **LLM01 Prompt Injection**, **LLM06 Excessive
  Agency**. ⚠️ Insecure Plugin Design folded into LLM06 + Supply Chain. Don't cite the 2023 list.
  Published 2024-11-17 (so cite as OWASP Foundation, 2024):
  <https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/>. Cited on the poster.
- **MITRE ATLAS** — primary scenario label, one technique per scenario (D13): AML.T0053 LLM
  Plugin Compromise, AML.T0051 / AML.T0051.001 (Indirect) Prompt Injection, AML.T0057 LLM Data
  Leakage. <https://atlas.mitre.org/>. The site fetch failed on 2026-10-27; add a retrieval date
  when citing.
- **HIPAA Security Rule, 45 C.F.R. § 164.312(b) (audit controls)** — the compliance hook for
  the hash-chained audit log. Confirm the edition year on eCFR before citing.
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

### 8.1 Healthcare-MSP stakes (the case-study framing)

- **Concentration risk.** The Provider manages about 30 client practices (chiropractic, physical
  therapy, allied health) from one self-hosted RMM platform, so one Provider-side failure exposes
  all of them at once (project report, Problem Identification).
- **Breach cost: IBM *Cost of a Data Breach Report 2026*, via Diaz (2026, Becker's Hospital
  Review).** The average healthcare breach costs **$6.64M**, down from $7.42M in 2025, and
  healthcare has been the costliest sector for the 13th straight year. AI-driven attacks rose
  **56%** year over year and add about **$1M** per malicious breach. Verified against Becker's
  on 2026-10-27. ⚠️ The **247-day** identify-and-contain figure is **all-industry**, not
  healthcare. The IBM primary was not retrieved, so cite as *(IBM, 2026, as cited in Diaz, 2026)*
  and list only Diaz.
- **HIPAA penalties: HHS annual civil monetary penalty inflation adjustment, effective
  2026-01-28** (Federal Register doc. 2026-01688). The annual cap is **$2,190,294** for every
  tier. The tier figures were verified via Mercer (2026, January 29),
  <https://www.mercer.com/en-us/insights/law-and-policy/hhs-adjusts-2026-hipaa-certain-aca-and-msp-monetary-penalties/>.
  ⚠️ The volume and pages used on the poster, *91*(18), 3665–3682, are not yet checked against
  the Federal Register itself. ⚠️ Wording differs: the poster says "per tier", the report table
  says "per category". Pick one and use it everywhere; the cap applies per calendar year to
  violations of an identical provision.

---

## 9. Citations used on the poster and executive summary

APA 7, as printed on the poster (`poster/poster-copy.md`). IBM is cited only through Diaz.

- Diaz, N. (2026, July 31). *Healthcare data breaches cost $6.64M on average: Report*. Becker's
  Hospital Review.
  https://www.beckershospitalreview.com/healthcare-information-technology/cybersecurity/healthcare-data-breaches-cost-6-64m-on-average-report/
- Li, J.-J., He, J., Shang, C., Kulshreshtha, D., Xian, X., Zhang, Y., Su, H., Swamy, S., & Qi, Y.
  (2025). *STAC: When innocent tools form dangerous chains for LLM agents* (arXiv:2509.25624).
  arXiv. https://doi.org/10.48550/arXiv.2509.25624
- National Institute of Standards and Technology. (2024). *The NIST Cybersecurity Framework
  (CSF) 2.0* (NIST CSWP 29). https://doi.org/10.6028/NIST.CSWP.29
- OWASP Foundation. (2024). *OWASP Top 10 for LLM applications 2025*.
  https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
- U.S. Department of Health and Human Services. (2026, January 28). Annual civil monetary
  penalties inflation adjustment. *Federal Register, 91*(18), 3665–3682.

Notes:
- **STAC version.** Title, authors and the 2025-09-30 first posting are verified; the DOI follows
  arXiv's standard pattern. v3 is dated 2026-07-19, and the notes in §2 were taken from v3, so
  cite the version you read.
- **STAC page reference.** The 91.2% / 483-case figures are from the full read on 2026-08-19, but
  the page or section has not been recorded. Add it before the final report.

---

## Open questions — status 2026-10-28

**Resolved:**
- [x] Threat model: Progent's benign user vs. STAC's user-channel adversary → **D9**: indirect
      prompt injection, option (b); STAC chains re-homed and cited "adapted from".
- [x] Concurrent sequence-level guardrails → **D10**: identified (MAGE, ARGUS, DSCC, ePCA) and
      positioned in the report; novelty claim narrowed (§2.1).
- [x] STAC repo checked for reusable chains → **2026-09-14**: none reusable (no RMM surface;
      CC BY-NC 4.0). Scenarios are original constructions, STAC-adapted in structure.
- [x] Scenario labelling → **D13**: one MITRE ATLAS technique per scenario (primary);
      Agent-SafetyBench failure mode as an optional secondary tag.
- [x] Agent model → **D4**: Ollama + Llama 3.1 8B.
- [x] Escape scoring → **D6**: deterministic per-scenario post-condition checker.
- [x] Scope → build completed and tagged `v1.0-capstone` (2026-10-28). AgentDojo integration
      (the D3 stretch goal) was not done and is future work.

**Still open before the final report:**
- [ ] Record the page or section for STAC's 91.2% / 483 figures (§9).
- [ ] Check the HHS Federal Register volume and pages, *91*(18), 3665–3682 (§8.1).
- [ ] Align "per tier" (poster) and "per category" (report) for the HIPAA cap (§8.1).
- [ ] Get the IBM *Cost of a Data Breach Report 2026* primary, or keep citing it through Diaz.
- [ ] Confirm the report's one-line characterisations of MAGE, ARGUS, DSCC and ePCA against
      their abstracts, and add full APA entries (§2.1).
- [ ] Keep the adaptive-attacker niche as **future work**; the evaluation did not include a
      re-planning attacker (see *Positioning statement*).
- [ ] Track down the Anthropic AI-enabled espionage publication cited by STAC §2.1 before using
      it (§8).
- [ ] Re-run the live suite under the current, shape-locked policy (issue #57); live results
      predate the policy change.

---

