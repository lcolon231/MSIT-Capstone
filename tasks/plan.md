# Implementation Plan — AI-Agent Containment Monitor (CIS 6950 Capstone)

> **Rewritten 2026-08-19** against `spec.md` v2, which is written against the Assignment 1
> rubric. The engineering barely changed; the *sequencing* and the *deliverables alongside it*
> changed a lot.
> **State:** greenfield. No `src/`, no `pyproject.toml`. Everything below is to be created.

## Governing principle

**Write the report chapter as each build phase finishes — not in November.**

The report is 60% of the grade and needs 40+ pages, ≥8 explained diagrams, screenshots, code
snippets, a user manual, and a compliance mapping. None of that can be reconstructed from
memory six weeks later, and Design + Implementation alone are 45 of 100 rubric points. Every
phase below therefore has a **Build** output and a **Report** output, and the phase is not done
until both exist.

Corollary: **screenshot every feature the first time it works.** Cheap now, expensive later.

## Rubric → phase map

| Rubric section | Pts | Delivered in |
|---|---|---|
| System Design and Architecture | 25 | Phase 1 (diagrams), Phase 4 (login/UI), Phase 6 |
| Implementation Process Documentation | 20 | Phases 2–5, written as you go |
| Abstract / TOC / Organization | 10 | Phase 7 |
| Proposed Solution and Requirements (+cost, ethics) | 10 | Phase 1 |
| Company Profile and Business Case | 5 | Phase 1 |
| Problem Identification | 5 | Phase 1 (research.md already covers *Review of Existing Technologies*) |
| Testing and QA | 5 | Phase 5 |
| Troubleshooting / Final System Overview | 5 | Phase 6 |
| User Training and Documentation | 5 | Phase 6 |
| Maintenance, Security, Compliance | 5 | Phase 6 |
| Review and Continuous Improvement | 5 | Phase 6 |
| Conclusion | 5 | Phase 7 |

## Architecture decisions (from `Decision Log.md`)

- **D1** sequence engine = explicit kill-chain state machine
- **D2** policy = narrow declarative YAML, trigger/check/enforce (AgentSpec structure)
- **D3** eval = custom tool suite + STAC-adapted chains — **now scoped to 6 attack / 4 benign**
- **D4** model = Ollama + Llama 3.1 8B behind a pluggable interface; stub model in CI
- **D5** gate = four classes: file delete, network send, data export, credential access
- **D6** escape scoring = per-scenario deterministic checker, no LLM judge
- **D7** positioning = checkpoint enforcement vs trajectory reasoning
- **D8** enforcement subset = DENY + GATE only (no agent-modifying actions)
- **D9** threat model = trusted operator; external indirect-prompt-injection adversary
- **D10** novelty scope = deterministic, inspectable policy-as-data sequence enforcement on a local open-weight agent
- **D11** monitor = separate process; loopback decision-and-dispatch primary, in-process scope cut
- **D12** retention = `(monitor session, resource principal)` live state + 24 h audit replay; logged expiry/eviction
- **D13** labels = exactly one MITRE ATLAS primary + optional Agent-SafetyBench secondary
- **D14** session bootstrap = trusted launcher injects a session-bound, dispatch-only transport
- **D15** lifecycle = session end/idle expiry clears live state, not within-lookback audit history
- **D16** canonical near miss = sequence returns `None`; ordinary D5 data-export rule gates
- **D17** design interface = normative documentation contract; Python skeleton deferred to implementation

## Phases

### Phase 1 — Case study foundation (report-first, ~1 week)

The only phase with no code. It exists because Company Profile, Problem Identification, and
Proposed Solution + Requirements are 20 rubric points that depend on nothing technical, and
because the requirements chapter defines what Phases 2–5 actually build.

- **Build:** none
- **Report:** Company Profile and Business Case (with org hierarchy diagram); Problem
  Identification (statement, impact analysis, security concerns, review of existing
  technologies — pull from `research.md`); Proposed Solution; Requirements Specification
  (system, hardware/software, security, ethical/professional, **estimated cost**)
- **Diagrams:** #1 org hierarchy, #2 current-state architecture, #3 proposed architecture

**Checkpoint:** ~10 report pages drafted, 3 diagrams done, topic confirmed with the instructor.

### Phase 2 — Monitor core (~2 weeks)

- **Build:** repo scaffold + quality gates; core value types; YAML policy schema and loader;
  per-call verdict engine with fail-closed default; argument-aware matchers; append-only JSONL
  audit log + replay
- **Report:** Implementation §1 (system setup and installation) and the first half of §2
  (feature implementation) with code snippets
- **Diagrams:** #5 data flow for a single tool call including the audit write

**Checkpoint:** a call is mediated → verdicted → logged → replayable. ≥80% coverage on
`src/monitor` and `src/policy`.

### Phase 3 — Sequence engine, the hero result (~1.5 weeks)

- **Build:** kill-chain state machine (named chains, session state, transitions); RMM mock
  domain; mediated dispatch; canonical chain
  `list_endpoints → list_shares → register_destination → export_records` blocked at sequence level while each
  call passes per-call checks; evasion cases (interleaving, reorder, session reset, duplicates)
- **Report:** Implementation §2 continued; the sequence section of Design
- **Diagrams:** #4 sequence state machine — the hero diagram, also the poster centrepiece

**Checkpoint:** the demo that carries the presentation and the poster. If everything after this
slipped, there would still be a capstone.

### Phase 4 — Gate, console, and agent loop (~2 weeks)

The phase the old plan was missing entirely, and the one the rubric most rewards.

- **Build:** approval gate for the four D5 classes, fail-closed on no approval; **Flask
  console — login page, live decision feed, pending-approval queue with working approve/deny,
  policy viewer, sequence-state inspector**; agent loop + Ollama client (stub model in CI);
  remaining mock domains (files, network, creds)
- **Report:** Implementation §2 (UI), §3 (security implementation — auth, session handling,
  access control, compliance alignment)
- **Diagrams:** #6 approval-gate flowchart, #7 login/session flow, #8 deployment / network zones
- **Screenshots:** login page, dashboard, a GATE being approved and denied, audit log view

**Checkpoint:** end-to-end — agent proposes a transfer, monitor gates it, operator approves in
the browser, decision lands in the audit log. This is the video demo.

### Phase 5 — Evaluation (~1 week, deliberately small)

- **Build:** scenario format + deterministic post-condition checkers (D6); **6 attack scenarios
  (≥3 chained) + 4 benign**; eval runner emitting false-approval / false-block / utility per
  domain and per attack; live run on the build box
- **Report:** Testing and Quality Assurance — test plan, test cases with expected vs actual,
  QA procedures, coverage, results tables

**Checkpoint:** metrics table + audit logs captured under `results/`, reproducible.

### Phase 6 — Operations documentation (~1.5 weeks)

Five rubric sections nobody enjoys writing and everybody skips. Worth **25 points** combined.

- **Docs:** user manual (basic + advanced tasks); training material / quick-start; FAQ and
  troubleshooting; maintenance plan (patching, monitoring with Prometheus/Grafana, security
  audits, helpdesk/ticketing, refresher training); **compliance mapping — HIPAA, NIST CSF 2.0,
  ISO/IEC 27001**; review and continuous improvement process
- **Report:** Implementation §5 troubleshooting (challenges, changes from plan, lessons
  learned), §6 final system overview, §7 user documentation, §8 maintenance and support,
  §9 review and continuous improvement

**Checkpoint:** every required heading has content. No placeholders.

### Phase 7 — Assembly and the other 40% (~2 weeks)

- Assemble the report: UWF title page, TOC, abstract, all headings in order, figure numbers and
  captions, references. **Verify ≥40 pages excluding title/abstract/references** — 20% penalty.
- Executive Summary (2–3 pages, A2)
- Poster (36×48, A3) — hero diagram centre, results table, conclusions, future directions
- Recorded presentation (A4) — 15–20 slides, 15–20 min, camera on, live console demo
- Practical Connection (A5) — 500+ words, APA, tie to MSP/healthcare IT practice
- AI usage disclosure per course policy

## Dependency graph

```
Phase 1 (case study, report)   ── independent, do first
        │
Phase 2 core types → policy loader → verdict engine → matchers
        ├── audit log (parallel-safe)
        └── Phase 3 sequence machine → RMM domain → canonical chain
                    │
            Phase 4 gate → console (login, feed, approvals) → agent loop → extra domains
                    │
            Phase 5 scenario format → suite → runner → live run
                    │
            Phase 6 operations docs → Phase 7 assembly
```

## Schedule (confirmed from Canvas 2026-08-19)

| Deliverable | Due | Points |
|---|---|---|
| **Idea Approval** | **Aug 28, 11:59pm** | 50 |
| Executive Summary | Nov 18, 11:59pm | 50 |
| Project Report | Nov 28, 11:59pm | 100 |
| Project Poster | Nov 30, 11:59pm | 50 |
| Practical Connection | Dec 2, 11:59pm | 50 |
| Final Recorded Presentation | Dec 3, 11:59pm | 100 |

> ⚠️ Canvas raw points (400 total) imply a different weighting than the syllabus
> (Report 60%, Presentation 15%, Poster 10%, Idea 5%, Practical 5%, Exec Summary 5%).
> If Canvas uses weighted assignment groups the syllabus percentages govern; if it uses raw
> points, the **Presentation is worth as much as the Report**. Check the Canvas Assignments
> page for group weights — it changes how much effort the video deserves.

**Working plan (report substantially done by Nov 18, since the Executive Summary must
summarise a finished project):**

| Window | Phase |
|---|---|
| **Aug 19 – Aug 28** | **Idea Approval submission** + Phase 1 case study started |
| Aug 29 – Sep 12 | Phase 1 finished (3 diagrams, ~10 report pages) + Phase 2 begins |
| Sep 13 – Sep 26 | Phase 2 monitor core complete |
| Sep 27 – Oct 8 | Phase 3 sequence engine (hero result) |
| Oct 9 – Oct 26 | Phase 4 gate + web console + agent loop |
| Oct 27 – Nov 3 | Phase 5 evaluation |
| Nov 4 – Nov 14 | Phase 6 operations documentation |
| Nov 15 – Nov 18 | Report assembly pass 1 → **Executive Summary due Nov 18** |
| Nov 19 – Nov 28 | Report polish, page count, headings check → **Report due Nov 28** |
| Nov 29 – Nov 30 | **Poster due Nov 30** |
| Dec 1 – Dec 3 | **Practical Connection Dec 2**, **Recorded Presentation Dec 3** |

Note the tail: four deliverables land in six days (Nov 28 – Dec 3). Poster and slides both
derive from finished report chapters, so build them from the report rather than from scratch —
but do not leave the video recording to Dec 3.

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| **Report under 40 pages** | 20% penalty | Write per phase, not at the end; 8 explained diagrams and screenshots carry real page count |
| **Missing required headings** | 10–20% penalty | Heading checklist in `todo.md`; verify in Phase 7 |
| **Presentation (15%) forgotten** | Course cannot be completed without it | On the schedule above; slides derive from report chapters |
| Console scope creep | Med | Flask + Jinja only. No SPA, no build step, no component library |
| Sequence engine over-blocks | Med | False-block guard test; legit register-then-export must pass |
| Live Ollama flakiness | Med | Stub model in CI; live runs manual on the build box |
| Four deliverables due Nov 28 – Dec 3 | High | Poster + slides derive from finished report chapters; record the video by Dec 1, not Dec 3 |
| Scenario authoring balloons | Low now | Capped at 6+4; STAC repo has reusable RMM chains |

## What changed from the previous plan

- **Added Phase 1** (case study + requirements + cost) — 20 rubric points that were unplanned
- **Added the web console** — the rubric names a main login page and a user interface; it also
  makes the D5 approval gate real instead of simulated, and supplies Implementation screenshots
- **Added Phase 6** — user manual, training, FAQ, maintenance, compliance, continuous
  improvement: 25 rubric points, previously absent
- **Cut the eval** from 15 attack + 10 benign to 6 + 4 — Testing is 5 points, and the reclaimed
  ~2 weeks went to Design and Implementation, which are 45
- **Demoted the literature work** — `research.md` now feeds one heading inside a 5-point
  section. It is finished. D10 (novelty vs concurrent work) no longer affects the grade.
- **Report writing moved into every phase** rather than being a November activity
