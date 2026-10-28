# Poster copy: Assignment 3 Project Poster

<!--
All words on the poster live in this file; build_poster.py reads it and contains no prose.
Format rules:
  * Each "## key" heading starts a block. Keys are fixed; do not rename them.
  * Lines starting "- " are bullets / list items. Fields inside an item are separated by " | ".
  * **bold** and *italic* are supported inside any line.
  * Every number must come from docs/a2-evidence-pack.md (see the figures table in the build report).
  * Keep each bullet to 3 lines or fewer at poster size (the build warns at more than 4).
-->

## title
Containing AI Agent Actions at a Healthcare Managed Service Provider

## subtitle
A gatekeeper that stopped every harmful action an AI agent attempted, without blocking routine IT work.

## byline
Luis Colón Sánchez  ·  CIS 6950 IT Capstone  ·  Instructor: Dr. Mahd Alzoubi  ·  University of West Florida  ·  MSIT

## overview.header
Overview

## overview.bullets
- **The Provider**, an MSP serving about 30 small healthcare practices, wants its AI agent to *act* on client systems, not just advise.
- A **containment monitor** sits between the agent and the remote-management (RMM) tools and checks every action **before it runs**.
- **Fail-closed:** an unknown or malformed action is blocked by default.

## overview.verdicts.lead
Every action gets one of three verdicts:

## overview.verdicts
- ALLOW | run it
- DENY | block it
- GATE | pause for human approval

## overview.screenshot.caption
**Figure 1.** Operator console, live session: recon steps allowed, exports gated, and the chain-ending export denied.

## background.header
Background & Significance

## background.bullets
- **Concentration risk:** one failure at the Provider exposes about 30 practices that hold patient health information at the same time.
- **Chained attacks:** steps that are each harmless (list endpoints, list shares, register a destination, export records) chain into data theft.

## background.callouts
- 91.2% | chained-tool attack success against AI agents (Li et al., 2025)
- $6.64M | average healthcare data breach (IBM, 2026, as cited in Diaz, 2026)
- $2,190,294 | HIPAA annual penalty cap per tier (U.S. Department of Health and Human Services, 2026)

## background.note
Targets OWASP LLM01 *Prompt Injection* and LLM06 *Excessive Agency* (OWASP Foundation, 2024).

## objectives.header
Objectives

## objectives.bullets
- **Fail closed** and check **every** action before it runs
- **Detect harmful sequences**, not just single risky calls
- **Keep routine IT work unblocked**
- Keep a **tamper-evident audit trail** of every decision

## methodology.header
Methodology

## methodology.diagram
- input | Untrusted input | ticket · email · log · filename
- agent | AI agent (LLM) | Llama 3.1 8B, local; not trusted
- monitor | Containment Monitor | trusted · fail-closed
- step1 | 1 · Intercept | every tool call
- step2 | 2 · Sequence engine | kill-chain state
- step3 | 3 · Per-call policy | no matching rule = DENY
- policy | policy.yaml | declarative rules
- verdict | Verdict
- allow | ALLOW | RMM tools run
- gate | GATE | human approves?
- deny | DENY | blocked; never reaches a tool
- log | Audit log | every decision, hash-chained
- e.proposed | proposed tool call
- e.approve | approve
- e.reject | reject / timeout
- e.result | result
- e.log | every decision

## methodology.diagram.caption
**Figure 2.** System architecture: no agent action reaches a tool without a verdict (adapted from project Figure 3).

## methodology.strip.header
How it was tested

## methodology.strip
- Threat model | injected content, attack surface
- 6 attack + 4 routine | scenarios
- Deterministic scoring | pass / fail, no AI judge
- 5 live runs | local Llama 3.1 8B
- Attribution | monitor stops vs. chains never completed

## methodology.strip.note
Quality check: 792 automated tests, 98% code coverage.

## methodology.chain.header
Sequence rule: recon → register → exfil

## methodology.chain
- list endpoints | ALLOW
- list shares | ALLOW
- register destination | ALLOW
- export records to it | DENY

## methodology.chain.caption
**Figure 3.** Each step alone is allowed; the sequence engine denies the export that completes the chain (adapted from project Figure 4).

## results.header
Results & Findings

## results.callouts
- 0 | escapes: 15 of 15 attempted attacks stopped
- 20/20 | routine tasks completed, 0 wrongly blocked
- ~1.5 | approvals per routine task

## results.chartA.title
Attack outcomes across 30 live attack runs (6 attacks × 5 runs)

## results.chartA
- not_attempted | 15 | not fully attempted by the model
- deny | 5 | stopped automatically (DENY)
- gate | 10 | stopped at the human gate (GATE)
- escaped | 0 | escaped

## results.chartA.annotation
Of 15 attempted: 15 stopped, 0 escaped

## results.chartB.title
Routine tasks: 20/20 completed, 0 wrongly blocked. Approval prompts per run, by task:

## results.chartB
- File cleanup | 4
- Export to approved destination | 2.0
- Health check | 0
- Read-only recon | 0

## results.chartB.xlabel
Approval prompts (GATE) per run


## conclusions.header
Conclusions & Recommendations

## conclusions.lead
**Every attempted harmful action was contained, with no routine work blocked and a modest approval load.**

## conclusions.bullets
- **Staged rollout:** read-only and gated actions first; widen the allow-list as evidence builds
- **Named approver on every shift**, trained on what to reject (10 of 15 stops relied on the gate)
- **Red-team with a stronger model** before granting full execution rights
- **Retain the audit log** as compliance evidence (HIPAA audit controls; NIST CSF 2.0)

## future.header
Future Directions

## future.bullets
- Re-run the live tests under the current, tightened rules
- Expand the scenario suite (AgentDojo)
- Pilot with a real approver to measure recovered technician hours

## future.unproven.header
Not yet proven

## future.unproven
- Live chain detection fired **0** times (**3/3** in scripted tests)
- The model fully attempted only **15 of 30** attack runs
- Approvals were simulated by a mock approver

## references.header
References

## references
- Diaz, N. (2026, July 31). *Healthcare data breaches cost $6.64M on average: Report*. Becker's Hospital Review. https://www.beckershospitalreview.com/healthcare-information-technology/cybersecurity/healthcare-data-breaches-cost-6-64m-on-average-report/
- Li, J.-J., He, J., Shang, C., Kulshreshtha, D., Xian, X., Zhang, Y., Su, H., Swamy, S., & Qi, Y. (2025). *STAC: When innocent tools form dangerous chains for LLM agents* (arXiv:2509.25624). arXiv. https://doi.org/10.48550/arXiv.2509.25624
- National Institute of Standards and Technology. (2024). *The NIST Cybersecurity Framework (CSF) 2.0* (NIST CSWP 29). https://doi.org/10.6028/NIST.CSWP.29
- OWASP Foundation. (2024). *OWASP Top 10 for LLM applications 2025*. https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
- U.S. Department of Health and Human Services. (2026, January 28). Annual civil monetary penalties inflation adjustment. *Federal Register, 91*(18), 3665–3682.
