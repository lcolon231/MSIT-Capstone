# TODO — AI-Agent Containment Monitor (CIS 6950 Capstone)

> Rewritten 2026-08-19 from `plan.md` v2. Every task has a **Build** and/or **Report** output.
> A task is done when both exist. Definition of Done for code tasks: `pytest -q`,
> `ruff check`, `ruff format --check`, `mypy src` all clean.
>
> **Screenshot every feature the first time it works.** Save to `docs/screenshots/`.

---

## Idea Approval — SUBMITTED ✅ (due Aug 28, 50 pts)

Confirmed submitted 2026-08-19; Canvas shows "Not Yet Graded". No further action.

- [ ] **Carry-over risk:** the submitted proposal claims an independent enforcement layer is
      "a genuine, unsolved need." Progent, AgentSpec, ePCA and DSCC all implement it. That is
      fine in a proposal, but it **must not survive into the Project Report** — the corrected
      framing is in `research.md` under *Positioning statement*.
- [ ] When the grade/feedback comes back, check whether the instructor approved the topic and
      whether any scope change was requested. Log it in `capstone/Capstone Check-ins.md`.
- [ ] The report reframes the proposal as an **industry case study for the Provider** (MSP
      serving healthcare practices). Confirm with Dr. Alzoubi if the shift from the proposal's
      framing is significant enough to warrant a note.

## Week 0 — housekeeping

- [x] ~~Confirm real due dates on Canvas~~ → done 2026-08-19; see `plan.md` schedule.
- [ ] **Check Canvas assignment-group weights.** Raw points (400 total) make the Presentation
      worth as much as the Report; the syllabus says 60% vs 15%. Which is live changes how much
      effort the video deserves.
- [x] ~~Decide: organisation named or confidential~~ → **confidential, "the Provider"** (2026-08-19)
- [ ] Download the UWF title page template and the sample TOC from Canvas.
- [ ] Read the course AI-usage policy; start an AI disclosure note now.

## Phase 1 — Case study foundation (no code)

### T1.1 Company profile and business case — 5 pts
- [x] Overview of the Provider (services, clients, size)
- [x] Business operations and infrastructure
- [x] Current IT and security landscape (RMM, monitoring, endpoints, client separation)
- [x] **Diagram #1 — organisational hierarchy** (required by rubric)
- [x] **Diagram #2 — current-state architecture**
- **Report:** §Project Initiation and Planning

### T1.2 Problem identification — 5 pts
- [x] Statement of the problem (LLM agents + tool access in a HIPAA environment)
- [x] Impact analysis (breach exposure, HIPAA reporting, client trust, financial)
- [x] Analysis of security concerns (prompt injection, excessive agency, chained actions)
- [x] Review of existing technologies — Progent, AgentSpec, CaMeL, LlamaFirewall,
      NeMo/Llama Guard, GuardAgent, ePCA, DSCC, MAGE, ARGUS. Done; do not expand.
- **Report:** §Identification of the Existing Problem

### T1.3 Proposed solution and requirements — 10 pts
- [x] Proposed solution narrative (monitor as reference monitor; "seccomp for tool calls")
- [x] **Diagram #3 — proposed solution architecture**
- [x] System requirements
- [x] Hardware and software requirements (build box spec, Ollama, Python, Flask)
- [x] Detailed security requirements (fail-closed, complete mediation, least privilege, audit)
- [x] Ethical and professional considerations — **except the AI usage disclosure (yours)**
- [x] **Estimated cost** — $53,400 one-time / $13,800 recurring at the $150/hr billable rate
- [x] **ROI calculation** — ~~ticket-time arithmetic with the Provider's real ticket mix~~ →
      resolved 2026-09-03 by **reframing** the economic analysis as recovered-technician-hour
      thresholds (Decision Log D19), **not** by obtaining the data — the Provider's PSA
      ticket-throughput figures were unavailable. See *Limitations of available data* in
      `report/phase1-chapters.md`.
- **Report:** §Project Requirements Specification

**Checkpoint:** ✅ ~5,250 words drafted (`report/phase1-chapters.md`), 3 diagrams rendered
(`docs/diagrams/`). Outstanding: AI disclosure, instructor sign-off.

---

## Phase 2 — Monitor core

### T2.1 Repo scaffold + quality gates
- [ ] `pyproject.toml` with pinned deps (`pytest`, `pytest-cov`, `ruff`, `mypy`, `pyyaml`,
      `flask`), `[dev]` extra, Python 3.11
- [ ] `src/` layout per spec §6, mirrored `tests/`, `.gitignore`
- [ ] `pytest -q` collects cleanly; `ruff` and `mypy` exit clean
- **Report:** Implementation §1 System Setup and Installation

### T2.2 Core value types
- [ ] `Verdict` enum, frozen `Decision` (verdict, `rule_id`, reason), `ToolCall`
- [ ] `evaluate(call, policy, state) -> Decision` — pure, fail-closed default
- [ ] Test: `Decision` is frozen; `evaluate` mutates nothing

### T2.3 Policy schema + YAML loader (D2)
- [ ] Field-frozen trigger / check / enforce schema
- [ ] Loader rejects unknown fields and malformed policy with clear errors
- [ ] `policies/rmm.yaml` loads and validates
- **Report:** code snippet of a policy rule — good Implementation content

### T2.4 Per-call verdict engine — criterion #2
- [ ] Matching rule returns ALLOW/DENY; no match → `DENY "no matching policy (fail-closed)"`
- [ ] Unknown tool → DENY; empty/None policy → all DENY
- [ ] Every `Decision` carries a non-null `rule_id`

### T2.5 Argument-aware matching — criterion #3
- [ ] `shell("ls")` ALLOW, `shell("rm -rf /")` DENY
- [ ] Anchored matchers resist `${IFS}`, base64, unicode homoglyphs, `../` traversal,
      look-alike domains (`attacker@example.com.evil.com`)
- [ ] Fuzz test: no dangerous-arg class silently ALLOWs

### T2.6 Audit log — JSONL writer + replay — criterion #8
- [ ] One JSONL record per decision: actor, tool, `rule_id`, verdict, reason, arg hash
- [ ] Replay reconstructs every decision of a run
- [ ] Append-only property test
- [ ] **Diagram #5 — data flow for a single tool call including the audit write**

**Checkpoint:** mediated → verdicted → logged → replayable. ≥80% coverage on `src/monitor`
and `src/policy`. 📸 Screenshot the CLI showing verdicts.

---

## Phase 3 — Sequence engine (hero result)

### T3.1 Sequence state machine (D1)
- [ ] `sequence.step(call, state)` advances named chains; returns DENY/GATE or None
- [ ] Session state explicit and inspectable; transitions deterministic
- [ ] Unit tests for the transition table incl. duplicate/idempotent steps

### T3.2 RMM mock domain + mediated dispatch — criterion #1
- [ ] `list_endpoints`, `list_shares`, `register_destination`, `export_records` over in-process state
- [ ] No tool executes without a `Decision`; unknown tool denied, not passed through
- [ ] Malformed tool call still yields a `Decision` — never crash-open

### T3.3 Canonical chain wired — criterion #4
- [ ] `list_endpoints → list_shares → register_destination → export_records` blocked at sequence level while
      no step is denied by per-call policy: first three `ALLOW`, transfer would ordinarily `GATE`,
      and the full sequence `DENY` takes precedence (assert both layers)
- [ ] Evasion: interleaving benign calls, reorder/partial chains, session-reset abuse,
      cross-session smear
- [ ] **False-block guard:** a legitimate register-then-export must NOT be blocked
- [ ] **Diagram #4 — sequence state machine** (hero diagram; poster centrepiece)
- **Report:** Design §sequence evaluation; Implementation §2

**Checkpoint:** the demo that carries the video and the poster. 📸 Screenshot the chain being
blocked at `export_records`.

---

## Phase 4 — Gate, console, agent loop

### T4.1 Approval gate (D5)
- [ ] file-delete, network-send, data-export, credential-access each → `GATE`
- [ ] No approval / timeout prevents execution (`ResultStatus.DENIED`); original verdict remains
      `GATE`, with a separate approval-resolution audit event
- [ ] Agent output cannot flip GATE→ALLOW (`approved=true`, persuasive `reason` both ignored)
- [ ] Pending-approval queue the console can read and resolve
- [ ] **Diagram #6 — approval gate flowchart**

### T4.2 Web console — login page ⭐ rubric explicitly requires this
- [ ] Flask app, session auth, **main login page**
- [ ] Dashboard: live decision feed from the audit log
- [ ] Pending approvals: working approve / deny
- [ ] Policy viewer (rendered YAML rules)
- [ ] Sequence-state inspector (which chains are part-way advanced)
- [ ] **Diagram #7 — login and session flow**
- [ ] 📸 Screenshots: login, dashboard, approve, deny, audit view
- **Report:** Implementation §2 User Interface, §3 Security Implementation (auth, sessions,
  role-based access, TLS note)

### T4.3 Agent loop + pluggable model client (D4)
- [ ] Model interface; Ollama/Llama-3.1-8B adapter + stub/recorded model for CI
- [ ] Integration test: every tool call mediated; gate blocks on no approval
- [ ] `python -m src.agent.run --task "..."` runs end to end
- [ ] **Diagram #8 — deployment / network zones**

### T4.4 Remaining mock domains
- [ ] files, network, creds over in-process state, no real egress
- [ ] Each has at least one GATE-class operation

**Checkpoint:** agent proposes a transfer → monitor gates → operator approves in the browser →
audit log records it. This is the video demo. 📸 Capture the whole flow.

---

## Phase 5 — Evaluation (scoped small — 5 rubric pts)

### T5.1 Scenario format + deterministic checker (D6)
- [ ] Scenario carries benign/attack tag, label, and a binary post-condition checker
- [ ] Checker inspects recorded tool state / log only — **no LLM judge**
- [ ] Same scenario twice → identical verdict

### T5.2 Scenario suite — revised criterion #7
- [ ] **6 attack (≥3 chained) + 4 benign** — down from 15+10
- [ ] Include one indirect-injection-via-tool-result scenario (ticket or log line carrying the
      payload — fits the MSP threat model, D9 option b)
- [ ] Check the STAC repo (`amazon-science/MultiTurnAgentAttack`) for reusable RMM chains
      before writing from scratch

### T5.3 Eval runner + metrics — criterion #6
- [x] `python -m src.eval.run --suite all --out results/` emits false-approval / false-block /
      utility, per domain and per attack
- [x] Live run on the build box with Ollama; capture metrics and audit logs — full-suite result:
      100% containment, 0% false-approval, 0% false-block, 100% utility
      (`docs/evaluation-results.md`, `results/issue-19/`)
- **Report:** Testing and Quality Assurance — test plan, cases, expected vs actual, QA
  procedures, coverage report, results tables

---

## Phase 6 — Operations documentation (25 rubric pts)

- [ ] **User manual** — basic and advanced operator tasks (`docs/user-manual.md`)
- [ ] **Training material** — quick-start / onboarding walkthrough (`docs/training.md`)
- [ ] **FAQ and troubleshooting tips** (`docs/faq.md`)
- [ ] **Maintenance plan** (`docs/maintenance-plan.md`) — patch schedule, performance monitoring
      (Prometheus/Grafana), security audits, helpdesk/ticketing, refresher training, feedback loop
- [ ] **Compliance mapping** (`docs/compliance-mapping.md`) — **HIPAA**, NIST CSF 2.0
      (Govern/Protect/Detect), ISO/IEC 27001
- [ ] **Review and continuous improvement** — review cadence, how audit findings feed back
- [ ] **Validate cost/ROI thresholds against real PSA data (D19)** — carry the
      recovered-technician-hour threshold analysis into *Review and Continuous Improvement*: once
      the Provider's ticket volume and average handling time are available, test the thresholds
      against actual operations rather than benchmarks.
- [ ] Implementation §5 — challenges, changes made during implementation, lessons learned
- [ ] Implementation §6 — final system overview, integration, final screenshots and diagrams

---

## Phase 7 — Assembly and the other 40%

### T7.1 Report assembly (60%)
- [ ] UWF title page; Table of Contents; Abstract
- [ ] **Heading checklist** — every A1 heading present and in order:
      Company Profile and Business Case · Organizational Hierarchy · Overview of the Company ·
      Business Operations and Infrastructure · Company's IT and Security Landscape ·
      Identification of the Existing Problem · Statement of the Problem · Impact Analysis ·
      Analysis of Security Concerns · Review of Existing Technologies · Proposed Solution ·
      Project Requirements Specification · System Requirements · Hardware and Software
      Requirements · Detailed Security Requirements · Ethical and Professional Considerations ·
      Estimated Cost · Design and Development · Detailed System Design Architecture ·
      Security Design Documentation · Main Login Page · System Communication · User Interface ·
      Process Communication · Implementation and Maintenance (§1–9) · Conclusion of the Project
- [ ] Figure numbers and captions on all 8 diagrams; each explained in prose
- [ ] References (APA)
- [ ] **Verify ≥40 pages excluding title page, abstract, references** — 20% penalty
- [ ] **Verify headcount consistency across all chapters** — the service desk is **three**
      technicians (the Service Lead is supervisory and escalation-only, not queue-carrying);
      confirm no chapter reverts to four (see Decision Log D19 amendment, 2026-09-03)
- [ ] Formatting: Times New Roman, 12 pt body / 14 pt headings, double-spaced, left-justified
- [ ] AI usage disclosure

### T7.2 Executive Summary (5%) — 2–3 pages
### T7.3 Poster (10%) — 36×48
- [ ] Title, name, course, instructor · overview · background and significance · objectives ·
      methodology · results and findings · conclusions and recommendations · future directions
- [ ] Hero diagram (#4) as the centrepiece; two fonts, consistent palette

### T7.4 Recorded presentation (15%) ⚠️ required to complete the course
- [ ] 15–20 slides; 15–20 minutes; camera on throughout; clear audio
- [ ] Intro/background · problem and objectives · scope · design · implementation ·
      post-implementation evaluation · lessons learned and future recommendations
- [ ] Include a live console demo (login → agent run → gate → approve)
- [ ] File named `Colon_Luis_ProjectTitle.mp4`

### T7.5 Practical Connection (5%) — 500+ words, APA
- [ ] Tie to MSP / healthcare IT practice; name specific frameworks (NIST, HIPAA, ISO 27001)
- [ ] Do **not** summarise the assignments — reflect on applying the knowledge
- [ ] File named `Colon_Luis_Practical_Connection.docx`
