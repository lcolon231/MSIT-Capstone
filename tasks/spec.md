# Spec: AI-Agent Tool-Call Containment Monitor — MSIT Capstone (CIS 6950)

> **Rewritten 2026-08-19** against the actual course requirements (Assignment 1 + syllabus).
> The previous version of this spec targeted a research contribution. The assignment is an
> **industry case study**: analyse an organisation, design a security solution, implement it,
> and document it across 40+ pages. This spec now governs both the software and the report.

## 0. What is actually being graded

| Deliverable | Weight | Assignment |
|---|---|---|
| **Project Report** (40+ pages, Times New Roman 12pt, double-spaced) | **60%** | A1 |
| Professional Presentation (recorded video, camera on, 15–20 slides, 15–20 min) | 15% | A4 |
| Project Poster (one page, 36×48 in) | 10% | A3 |
| Idea Project | 5% | — |
| Practical Connection (500+ words, APA) | 5% | A5 |
| Executive Summary (2–3 pages) | 5% | A2 |

**Assignment 1 rubric — where the 60% actually sits (100 pts):**

| Rubric section | Pts | Status |
|---|---|---|
| System Design and Architecture — ≥5 fully explained diagrams, DFDs, login page, UI | **25** | ⚠️ not started |
| Implementation Process Documentation — setup, features, security, code snippets, screenshots | **20** | ⚠️ not started |
| Abstract, Title Page, TOC, Organization | 10 | not started |
| Proposed Solution and Requirements — incl. **cost** and **ethics** | 10 | partial |
| Company Profile and Business Case — incl. **org hierarchy diagram** | 5 | not started |
| Problem Identification — statement, impact, security concerns, review of existing tech | 5 | ✅ research.md covers this |
| Testing and Quality Assurance | 5 | planned |
| Troubleshooting and Final System Overview | 5 | not started |
| User Training and Documentation — manuals, training material, FAQs | 5 | not started |
| Maintenance, Security, Compliance | 5 | not started |
| Review and Continuous Improvement | 5 | not started |
| Conclusion and Outcomes | 5 | not started |

**There is no rubric line for literature review, related work, or novelty.** The Progent /
AgentSpec / STAC reading feeds exactly one heading — *Review of Existing Technologies*, inside
a 5-point section. It is done; do not add to it. `research.md` is now a supporting file, not a
deliverable.

**Penalties:** 25% late; **20% if under 40 pages**; 10–20% for missing required headings.

## 1. Organisation (case study subject)

**Subject:** a managed service provider delivering IT and security operations to small
healthcare practices (chiropractic / allied health). Referred to as **"the Provider"** or by
name at the author's discretion; the assignment explicitly permits "private" or "confidential"
if the organisation requests it.

Why this organisation fits:
- Real, documentable IT and security landscape: RMM tooling, remote-monitoring server,
  per-client environments, an existing NIDS dashboard.
- **HIPAA** applies — gives the compliance chapter genuine teeth rather than a generic
  ISO 27001 gesture.
- Automation with tool access (RMM agents executing actions on client endpoints) is already
  the operating model, so "what if an LLM agent drives these tools" is a natural, defensible
  business case rather than a hypothetical.

**Required company content (rubric §2):** overview, organisational hierarchy **diagram**,
business operations and infrastructure, current IT and security landscape.

## 2. Problem statement (report §Problem Identification)

The Provider is moving toward LLM-driven automation of routine IT operations — ticket triage,
endpoint remediation, log review, client reporting. Those agents need tool access: run a
command, read a file, send a message, touch a billing or PHI-adjacent record. An LLM agent is
non-deterministic and, per Zverev et al., cannot reliably separate instructions from data;
prompt injection reaching it through a ticket, an email, or a log line can redirect its
actions.

Existing controls do not cover this. Content moderation judges text, not actions. Per-call
allowlists judge one call at a time. **A sequence of individually-permitted calls can be
collectively harmful** — the canonical case being
`get_balance → list_payees → add_payee → transfer_funds`, where every step is legitimate and
only the composition is fraud. STAC (AWS AI Labs, 483 verified cases) measures this class of
attack succeeding against frontier agents **91.2%** of the time.

For a HIPAA-covered environment, an agent chaining permitted calls into an exfiltration or a
destructive action is a reportable breach, not an inconvenience.

## 3. Proposed solution

A **fail-closed runtime containment monitor** sitting between the agent and its tools. Every
tool call is intercepted and receives **ALLOW / DENY / GATE** *before* execution, judged by
what the call is — never by what the agent says about it. Three enforcement layers:

1. **Per-call, argument-aware policy** — declarative YAML; no matching rule means DENY.
2. **Stateful sequence evaluation** — a kill-chain state machine that recognises named
   malicious chains whose individual steps all pass per-call checks.
3. **Human approval gate** — four irreversible classes (file delete, network send, fund
   transfer, credential access) route to a human via a web console; no approval means DENY.

Plus an **append-only JSONL audit log** with a traceable `rule_id` on every decision, and a
**web console** for operators (login, live decision feed, pending approvals, policy viewer,
sequence-state inspector).

Framing for the report: *seccomp for tool calls* — a reference monitor (Anderson 1972) applying
least privilege and fail-safe defaults (Saltzer & Schroeder 1975) to agent actions.

## 4. Tech stack

- **Python 3.11+**; `pytest` + `pytest-cov`, `ruff`, `mypy`; deps pinned in `pyproject.toml`
- **Agent runtime:** Ollama, **Llama 3.1 8B** (Q4), GPU-resident (i7-12700K / 32 GB / RTX 4060
  8 GB), behind a pluggable model interface (D4)
- **Policy:** declarative YAML, trigger / check / enforce structure borrowed from AgentSpec (D2)
- **Sequence engine:** explicit state machine (D1)
- **Web console:** **Flask + Jinja templates + session auth** (no SPA — keep it small; the
  rubric wants a login page and a usable UI, not a framework showcase)
- **Diagrams:** draw.io / Mermaid exported to PNG for the report
- No cloud services, no network egress from the agent; all tools are mocks over in-process state

## 5. Commands

```powershell
# Setup
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
ollama pull llama3.1:8b

# Run the console (login page + dashboard + approvals)
python -m src.web.app                      # http://localhost:5000

# Run an agent task through the monitor
python -m src.agent.run --task "remediate ticket 4821"

# Red-team evaluation
python -m src.eval.run --suite all --out results/

# Quality gates
pytest -q
pytest --cov=src --cov-report=term-missing
ruff check src tests ; ruff format src tests ; mypy src
```

## 6. Project structure

```
src/
  monitor/      → verdict engine, ALLOW/DENY/GATE types, fail-closed default
  monitor/sequence.py → kill-chain state machine
  monitor/gate.py     → approval gate + pending-approval queue
  policy/       → YAML loader + schema validation
  agent/        → agent loop, Ollama client (pluggable), mediated dispatch
  tools/        → mock tools over in-process state (banking, files, network, creds)
  audit/        → append-only JSONL writer + replay
  eval/         → red-team runner, metrics
  web/          → Flask console: login, dashboard, approvals, policy view
policies/       → *.yaml containment policies
scenarios/      → red-team scenarios + deterministic post-condition checkers
tests/          → mirrors src/
results/        → eval outputs
docs/
  diagrams/     → the ≥5 required diagrams (source + exported PNG)
  screenshots/  → console + CLI captures for the Implementation chapter
  user-manual.md, training.md, faq.md
  maintenance-plan.md, compliance-mapping.md, cost-estimate.md
report/         → chapter drafts, assembled into the 40+ page .docx
tasks/          → spec.md (this), plan.md, todo.md
```

## 7. Required diagrams (rubric §5 — 25 pts, the single largest section)

Minimum five "fully explained"; produce **eight** so the section is unambiguously complete.
Each needs a figure number, a caption, and a paragraph of explanation in the report.

1. **Organisational hierarchy** of the Provider (required by rubric §2)
2. **Current-state architecture** — Provider + client environments, RMM, monitoring, data flows
3. **Proposed solution architecture** — agent → monitor → tools, showing where the monitor sits
4. **Sequence state machine** — the kill-chain automaton (the hero diagram; also the poster centrepiece)
5. **Data flow diagram** for a single tool call, including the audit-log write
6. **Approval gate flowchart** — GATE → operator console → approve/deny → outcome
7. **Login and session flow** (rubric explicitly names a main login page)
8. **Deployment / network zones** — where the monitor runs relative to agent and tools

## 8. Success criteria

**Software (unchanged from the original spec — these still hold):**
1. **Complete mediation** — no tool executes without a `Decision`; test-proven.
2. **Fail-closed** — unknown tool or no matching rule → `DENY`; test-proven.
3. **Argument awareness** — `shell("ls")` ALLOW vs `shell("rm -rf /")` DENY.
4. **Stateful sequence** — the canonical chain blocked at the *sequence* level while each call
   passes per-call checks. Unit test + red-team scenario.
5. **Approval gate** — the four classes route to GATE; no approval → DENY; agent output cannot
   flip GATE→ALLOW.
6. **Metrics** — false-approval, false-block, utility, per domain and per attack.
7. **Suite scale (revised)** — **≥6 attack scenarios (≥3 chained) + ≥4 benign.** Reduced from
   15+10: Testing is 5 rubric points and the original scope consumed ~4 weeks better spent on
   Design and Implementation (45 points).
8. **Auditability** — JSONL log fully reconstructs a run; replay test.
9. **NEW — Operator console** — login page, live decision feed, working approve/deny on a
   pending GATE, policy viewer. Required by rubric §5 and §6; also makes the human gate real
   rather than simulated.

**Report:**
10. ≥40 pages excluding title page, abstract, references.
11. Every required heading from Assignment 1 present, in order.
12. ≥8 diagrams, each captioned and explained.
13. Cost estimate, HIPAA + NIST CSF 2.0 + ISO 27001 mapping, maintenance plan, user manual,
    training material, FAQ.
14. Screenshots of the working console and CLI in the Implementation chapter.

## 9. Code style

Python 3.11, full type hints, small pure functions for anything a verdict depends on,
dataclasses for value types, `snake_case`, ruff defaults. The verdict function stays pure:

```python
class Verdict(Enum):
    ALLOW = "allow"
    DENY  = "deny"
    GATE  = "gate"

@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    rule_id: str          # always traceable
    reason: str

def evaluate(call: ToolCall, policy: Policy, state: SequenceState) -> Decision:
    """Fail-closed: no matching ALLOW rule => DENY. Pure; no side effects."""
    if (seq := policy.sequence.step(call, state)) is not None:
        return seq
    if rule := policy.match(call):
        return rule.decide(call)
    return Decision(Verdict.DENY, "default", "no matching policy (fail-closed)")
```

## 10. Boundaries

- **Always:** fail-closed default; every decision written to the audit log with a traceable
  `rule_id`; 100% of tool calls mediated; `pytest` + `ruff` before a commit; the verdict stays
  independent of the agent's own text; **capture a screenshot whenever a feature first works**
  (the Implementation chapter needs them and retrofitting is painful).
- **Ask first:** adding a dependency; changing the policy YAML schema; changing a metric
  definition; enabling any real network or filesystem access.
- **Never:** let agent output influence a verdict; use an LLM judge in a success metric; weaken
  a policy or delete a scenario to improve numbers; commit real secrets, real client data, or
  anything PHI; reintroduce the proposal's "genuine, unsolved need" framing.

## 11. Scope-cut order if time runs short

Cut from the top. **Never** cut the fail-closed core, the banking chain demo, the console
login page, or the report's required headings.
1. Extra mock-tool domains — shrink from four to **banking + files**
2. Reduce chained scenarios but keep the canonical banking chain
3. Drop the Qwen2.5 swap-in experiment
4. Console reduced to login + decision feed + approvals (drop policy viewer / state inspector)
5. Last resort: approval gate logs what it *would* gate instead of being interactive —
   but keep the login page and dashboard, because the rubric names them

## 12. Open items

- [ ] **Confirm real due dates on Canvas.** The section syllabus file is named *Summer-2026*,
      the grading table says "Semester Two", and the check-ins doc lists Nov 18 / Nov 28 /
      Nov 30 / Dec 2. These do not obviously agree, and the **15% recorded presentation** is
      absent from the check-ins doc entirely. Verify before committing to the plan schedule.
- [ ] Confirm with Dr. Alzoubi that an AI-agent security monitor is an approved topic
      (Assignment 1: "Other technical topics are welcomed with instructor approval").
- [ ] Confirm whether the organisation is named or treated as confidential.
- [ ] **D9** — threat model: Progent's benign-user model vs STAC's user-channel adversary.
      For this report, the MSP framing favours **indirect injection** (malicious content
      arrives in a ticket or log line, the operator is trusted) — likely option (b).
- [ ] Disclose AI tool usage per the course policy.
