# Project Report — Phase 1 Chapters (Draft v3)

> **Draft v3, 2026-08-19.** Covers Assignment 1 rubric sections 2, 3 and 4 — Company Profile
> and Business Case (5 pts), Problem Identification (5 pts), Proposed Solution and Requirements
> (10 pts). Twenty points, no code required.
>
> **v3:** all placeholders resolved except the AI-usage disclosure, which is yours to write.
> Confidential organisation ("the Provider"), 8 staff / ~30 client practices, MeshCentral on a
> hosted VPS, a read-only AI triage pilot in progress, a mature compliance programme, and a
> cost model priced at the billable rate. Regulatory and breach-cost figures are from verified
> 2026 sources (listed at the end).
>
> Headings match the Assignment 1 required structure exactly — do not rename them.

---

# Project Initiation and Planning

## Company Profile and Business Case

### Overview of the Company

The subject of this case study is a regional managed service provider delivering outsourced
information technology and security operations to small healthcare practices. At the
organisation's request it is referred to throughout this report as **"the Provider"**, and
identifying details have been generalised.

Operational and organisational details in this chapter are drawn from the author's direct
professional knowledge of the organisation, generalised at its request. Where quantitative claims
are used in the economic analysis, their basis and limitations are stated in *Limitations of
available data*.

The Provider employs eight staff, including one part-time contracted compliance consultant, and
serves approximately thirty client practices — predominantly chiropractic, physical therapy and
allied health clinics with between three and forty employees each.

The Provider's clients share a common profile that defines its risk exposure. They are too small
to employ dedicated IT staff. They operate electronic health record systems that place them
squarely within the scope of the Health Insurance Portability and Accountability Act. And they
depend almost entirely on their service provider for their security posture — a practice manager
is typically the most technically capable person on site.

This concentration of responsibility is the single most important characteristic of the
Provider's environment. A control failure at the Provider is not one organisation's incident. It
is a potential simultaneous exposure across thirty practices, every one of which holds protected
health information.

Revenue derives from recurring per-endpoint and per-seat managed services contracts,
supplemented by project work such as practice relocations, EHR
migrations and security assessments. Margin in this business is a direct function of how many
endpoints each technician can support, which makes automation not a convenience but the central
economic lever of the firm.

### Organizational Hierarchy

*See Figure 1 — Organizational Hierarchy.*

The Provider operates the flat structure typical of firms at this scale. The Owner/Principal
holds overall accountability and also serves as the Security Official required under the HIPAA
Security Rule §164.308(a)(2). Three functions report to the Principal:

- **Service Delivery** — a Service Lead and three technicians handling the ticket queue,
  endpoint remediation and client escalations. This is the majority of headcount and the
  primary consumer of any automation.
- **Infrastructure** — a single Systems Engineer responsible for the remote monitoring and
  management platform, backup infrastructure, network hardware and the Provider's own internal
  systems.
- **Client Success and Compliance** — one coordinator handling onboarding, business associate
  agreements, HIPAA documentation and audit support.

A part-time contracted vCISO provides compliance advisory on a retained basis.

Two structural observations follow from this chart, and both motivate the design choices later
in this report. First, **there is no dedicated internal security function** — security is a
responsibility distributed across people whose primary duties lie elsewhere. Second, **the
infrastructure function is a single point of knowledge**: one engineer owns the platform that
reaches every client endpoint. Controls in this environment must therefore enforce policy
automatically rather than depend on continuous human vigilance, because the vigilance budget is
genuinely small.

### Business Operations and Infrastructure

Day-to-day operations centre on a ticket queue. Monitoring alerts, client email and telephone
requests, and scheduled maintenance tasks converge into a professional services automation
platform from which technicians work. The Provider's service desk is staffed by three technicians
handling reactive and scheduled work across the managed client base, with the Service Lead in a
supervisory and escalation role rather than carrying queue work. The overwhelming majority of the
work is routine: password resets, printer and peripheral faults, software installation, disk space
remediation, patch failures and backup verification. Precise ticket-throughput figures were not
available for this study (see *Limitations of available data*), so the economic analysis in this
report is expressed in recovered technician hours rather than per-ticket savings.

The technical backbone is a self-hosted **MeshCentral** remote monitoring and management
deployment, with agents installed on every managed endpoint. These agents are, in security
terms, the most consequential asset the Provider owns. Each one can execute commands, transfer
files and initiate remote sessions on a machine that may store or access protected health
information. Agent-to-server communication is authenticated and TLS-encrypted, and the server runs on a
hosted virtual private server at a commercial cloud provider.

That hosting choice carries a consequence worth stating plainly: the RMM server presents a
**public listener on the open internet**. It is the Provider's highest-privilege asset, it is
reachable from anywhere, and it is the single point through which every managed endpoint can be
commanded. Any additional actor granted access to that platform — including an autonomous one —
inherits that reach.

Supporting systems include a backup and disaster recovery platform, an email security gateway,
a commercial endpoint detection and response product, and an
internally developed network intrusion detection dashboard used to surface anomalous traffic
across client networks.

*See Figure 2 — Current-State Architecture.*

### Company's IT and Security Landscape

The Provider's existing security programme is credible for a firm of its size and maps
recognisably onto the six functions of the NIST Cybersecurity Framework 2.0:

| CSF 2.0 Function | Existing controls |
|---|---|
| **Govern** | Tailored HIPAA policies and procedures reviewed annually; business associate agreements with every client; designated Security Official; documented annual risk assessment |
| **Identify** | Asset inventory maintained through the RMM platform; client network documentation |
| **Protect** | Multi-factor authentication on administrative accounts; role-based RMM permissions; endpoint protection; encrypted backups; patch management |
| **Detect** | NIDS dashboard; EDR alerting; RMM monitoring policies; regular internal audits |
| **Respond** | Documented and periodically **tested** incident response procedure; defined escalation path; client notification templates |
| **Recover** | Tested backup restoration; disaster recovery runbooks |

This is a mature programme for a firm of eight people, and that maturity sharpens rather than
softens the finding. **Every control listed above is documented, tested and audited — and every
one of them assumes the actor performing an administrative action is a human technician**: an
actor whose intent can be inferred from context, whose behaviour is bounded by training and
judgement, and who can be held accountable afterwards.

The Provider is now piloting automation that removes that actor from the loop. There is no
policy, no procedure and no technical control in the existing programme that governs what an
autonomous, non-deterministic actor is permitted to do with the same privileges. That is the
single uncovered area in an otherwise complete framework, and it is the subject of this project.

### Business Case

Technician time is the Provider's dominant cost, and the ratio of endpoints to technicians
determines whether the firm is profitable. Large language model agents capable of reading a
ticket, diagnosing a routine fault, executing a remediation through the RMM platform and closing
the ticket represent a step change in that ratio.

The Provider has begun evaluating this capability. A pilot currently in progress applies a
language model to the ticket queue in a strictly **read-only** capacity: the agent reads incoming
tickets, summarises them, correlates them against monitoring alerts and prior tickets, and drafts
a suggested diagnosis and remediation. A technician then reviews the suggestion and performs the
work manually.

The pilot demonstrates the value clearly — triage time falls, and the suggested remediations are
usually correct. It also demonstrates the ceiling. Every minute saved in diagnosis is spent again
in execution, because the agent is not permitted to act. **The agent has been given the analysis
but withheld the hands, and the analysis was never the expensive part.**

The reason for that restriction is not technical. The agent could be granted RMM tool access
tomorrow. It is withheld because no control exists that would make that access acceptable in a
HIPAA-covered environment, and the Provider's compliance programme — tested, audited, and
otherwise complete — has no answer for an autonomous actor holding administrative privilege.

That constraint is the business problem. Extending the pilot means granting an autonomous agent
the ability to execute commands on client endpoints — which means granting it access to systems
containing protected health information. The consequences of getting that wrong are quantified
in the Impact Analysis below, but the summary is that a single reportable breach would cost the
Provider more than the firm's annual technology budget, and could plausibly end it.

**The business case for this project is therefore not that the monitor reduces an existing
risk. It is that the monitor is the control that makes the automation adoptable at all.**
Without an independent enforcement layer, the residual risk of autonomous tool use in a
HIPAA-covered environment cannot be reduced to a level the Provider can accept, the pilot cannot
expand, and the margin improvement that motivated it remains unrealised.

The control carries a secondary benefit. Its decision log is auditable evidence of how
autonomous systems are governed — the kind of documentation a client's compliance officer, or an
Office for Civil Rights investigator, will eventually ask to see.

---

# Identification of the Existing Problem

## Statement of the Problem

Large language model agents act on the world through tool calls. When an agent is given tools
that execute commands, read and write files, transmit network traffic or access credentials, its
output is no longer text — it is action. In a healthcare IT environment, that action touches
protected health information.

Three properties of these systems combine to create a security problem that the Provider's
existing controls do not address.

**Agents are non-deterministic.** The same input can produce different tool calls across runs.
Any control that depends on predicting agent behaviour cannot offer a guarantee.

**Agents cannot reliably separate instructions from data.** Zverev et al. (ICLR 2025)
demonstrated that no tested model achieves high separation between the two, and that canonical
mitigations either fail to help or cost substantial utility. An instruction embedded in a support
ticket, a forwarded email, a log line or a filename may be interpreted by the agent as a
directive. This is indirect prompt injection, and Microsoft's published security guidance is to
assume it is inevitable and to design systems that contain it rather than systems that prevent
it. For the Provider this is not hypothetical: ticket bodies are written by client staff, and
the agent must read them to do its job.

**Harm can be distributed across individually permitted actions.** This is the property existing
controls miss most completely, and it is the focus of this project. A per-call allowlist
evaluates one tool call at a time and asks whether that call is permitted. It cannot express the
fact that a *sequence* of permitted calls may be collectively malicious. The canonical
illustration in the Provider's environment is an exfiltration chain — enumerate the managed
endpoints, list the shares that hold patient records, register a new export destination, then
export those records to it (`list_endpoints → list_shares → register_destination →
export_records`) — in which every step is a legitimate RMM operation an administrator performs
routinely, and only the composition constitutes a breach. Each action falls within the agent's
legitimate remit; the impermissible disclosure lives in their sequence, not in any one call.

STAC (Li et al., AWS AI Labs, 2026) constructed and validated 483 such attack chains and measured
an average final attack success rate of **91.2%** against production agents including GPT-4.1,
exceeding 90% for seven of the eight agents tested. Their conclusion states the problem this
project addresses: *"defending tool-enabled agents requires reasoning over entire action
sequences and their cumulative effects, rather than evaluating isolated prompts or responses."*

**The problem, stated precisely:** the Provider requires an enforcement mechanism governing what
an autonomous agent may do with its tools — one that is independent of the agent, deterministic
in its verdicts, aware of the arguments each call carries, capable of recognising malicious
sequences assembled from individually permitted calls, and fully auditable after the fact.

## Impact Analysis

**Regulatory exposure.** An impermissible disclosure of PHI triggers the HIPAA Breach
Notification Rule: notification to every affected individual, to the Department of Health and
Human Services, and — for breaches affecting 500 or more individuals — to prominent media
outlets serving the affected area. Civil monetary penalties are tiered by culpability. The
amounts below took effect **28 January 2026** following the annual inflation adjustment:

| Tier | Culpability | Minimum per violation | Maximum per violation | Annual cap per category |
|---|---|---|---|---|
| 1 | Reasonable efforts, unaware | $145 | $73,011 | $2,190,294 |
| 2 | Lack of oversight, reasonable cause | $1,461 | $73,011 | $2,190,294 |
| 3 | Wilful neglect, rectified within 30 days | $14,602 | $73,011 | $2,190,294 |
| 4 | Wilful neglect, not rectified | $73,011 | $2,190,294 | $2,190,294 |

The tier matters enormously here. Deploying an autonomous agent with broad tool access and *no
governing control* would be difficult to characterise as anything other than lack of oversight
or wilful neglect — Tier 2 at best, with a minimum of $1,461 per violation and an annual cap
above $2.19 million. Deploying the same agent behind a documented, auditable enforcement layer
is a materially different regulatory posture, and the audit log is the evidence.

**Financial exposure.** IBM's *Cost of a Data Breach Report 2026* places the average healthcare
data breach at **$6.64 million** — the costliest sector for the thirteenth consecutive year, ahead
of financial services at $6.29 million, against a cross-industry average of $4.99 million. The
same report found the mean time to identify and contain a breach rose to **247 days**, and — most
directly relevant here — that **AI-driven attacks rose 56% year over year and added approximately
$1 million to the average cost of a malicious breach.**

Those figures describe organisations far larger than the Provider, and a proportionate incident
would be smaller in absolute terms. The relevant comparison is not to the industry average but
to the Provider's own balance sheet: even a fraction of that cost exceeds the firm's annual
revenue from a substantial share of its client base.

**Operational exposure.** An incident implicating the RMM platform would require suspending
automation across all clients pending investigation. That platform is the delivery mechanism for
the Provider's entire service — its unavailability is not a degraded service, it is no service.

**Reputational exposure.** The Provider's product is trust. Clients outsourced precisely because
they cannot manage security themselves. A breach *caused by the Provider's own automation* is
qualitatively worse than one it failed to prevent at a client site, and across a base of thirty
practices connected by professional referral networks, word travels.

**Blast radius.** The multiplier is the point. A compromise of the Provider's agent tooling is
not a single practice's incident. It is a potential simultaneous exposure of PHI across every
managed client.

## Analysis of Security Concerns

Mapping to the OWASP Top 10 for LLM Applications (2025) and the OWASP Agentic AI Threats and
Mitigations guidance (2025):

**LLM01 — Prompt Injection.** The Provider's agents ingest untrusted content by design: ticket
bodies submitted by client staff, forwarded emails, log excerpts, filenames. Each is an injection
vector. Indirect injection arriving through *tool results* is the specific concern, because the
content reaches the agent after it has already begun a legitimate task and established context.

**LLM06 — Excessive Agency.** RMM agents hold broad privilege by necessity. An LLM agent driving
them inherits that privilege. Absent explicit scoping, the agent's action space is the union of
everything the RMM platform can do on every managed endpoint.

**Tool misuse.** A legitimate tool invoked with harmful arguments — a shell command that
destroys rather than diagnoses, a file read against a PHI-bearing path, a network transmission to
an attacker-controlled host.

**Chained action risk.** Individually permitted calls composing into harm, as described above.
No standard agentic-AI control framework covers this case, which is precisely why it warrants a
purpose-built control rather than a configuration change to an existing product.

**Internet-exposed control plane.** The RMM server presents a public listener. This is an
accepted and mitigated risk today — authentication, MFA and TLS — but it means that any
compromise of an actor authorised to use that platform is immediately a compromise reaching
thirty client networks. An autonomous agent driven by injected instructions is exactly such an
actor.

**Insufficient auditability.** If an agent takes an action that later proves harmful, the
Provider must reconstruct exactly what was requested, what was permitted, under which rule, and
why. Without decision-level logging there is no answer to a regulator's question, and no way to
distinguish a control failure from a policy gap.

**Approval fatigue.** The naive mitigation — require human confirmation for everything — fails
predictably. Turan (2026) models the reviewing human as a fatiguing resource rather than an
infinite oracle. A gate that fires constantly degrades into rubber-stamping, which is worse than
no gate at all because it manufactures the appearance of oversight while providing none. With
three technicians, the Provider's review capacity is measured in seconds per day.

## Review of Existing Technologies

**Content moderation systems** — NeMo Guardrails (Rebedea et al., 2023), Llama Guard (Inan et
al., 2023) — classify text as harmful or benign. They are not action-aware. Whether `rm -rf /`
should execute is not a property of the surrounding text; it is a property of the action's
irreversibility. Necessary, but not sufficient.

**Per-call runtime enforcement.** Progent (Shi et al., 2025) applies symbolic rules over tool
names and arguments under a default-deny posture, reducing attack success from 39.9% to 1.0% on
the AgentDojo benchmark. AgentSpec (Wang, Poskitt & Sun, ICSE 2026) provides a declarative
trigger/check/enforce policy language, preventing unsafe execution in over 90% of code-agent
cases with overhead measured in milliseconds. Both validate the architectural approach adopted
here, and both enforce at discrete execution checkpoints. AgentSpec's authors state the
resulting limitation directly: their system *"lacks support for trajectory-based safety
analysis."* Progent's stated scope excludes *"attacks that operate within the least privilege
for accomplishing the user task"* — which is exactly what a chain of individually permitted calls
is.

**LLM-based guardrails.** GuardAgent (Xiang et al., ICML 2025) generates guardrail code from
natural-language requirements; MAGE (Wang et al., 2026) maintains a safety-focused shadow memory
across the execution trajectory. Both place a probabilistic component inside the enforcement
path. AgentSpec's own experiment is instructive: LLM-generated rules achieved 95.56% precision
but only **70.96% recall**, missing roughly 29% of unsafe cases. For a control whose entire
purpose is containing a non-deterministic actor, reintroducing non-determinism into the control
is a poor trade.

**Architectural separation.** CaMeL (Debenedetti et al., 2025) isolates trusted control flow from
untrusted data through a custom interpreter, achieving provable security on 77% of AgentDojo
tasks. ARGUS (Weng et al., 2026) audits causal provenance from evidence through to action. Both
are rigorous; both require re-architecting the agent, which places them out of scope for a
provider adopting off-the-shelf tooling.

**Sequence-aware enforcement.** Recent work addresses composition directly. DSCC (Schneider et
al., Microsoft AI, 2026) composes per-tool policies into a chain-level policy under a
monotonicity invariant, with runtime taint tracking. ePCA (Wu et al., 2026) requires agents to
formalise their intentions into first-order logic verified by an SMT solver. Both demonstrate
that deterministic sequence-aware enforcement is achievable. ePCA depends on the agent declaring
its own intent for verification — a dependency this project deliberately avoids, since the
monitor's independence from the agent is what makes it trustworthy under adversarial conditions.
DSCC reports policy-blocking rates but no adversarial evaluation.

**Conclusion of the review.** The individual mechanisms this project assembles are established
in the literature, and the design borrows from them deliberately rather than reinventing them.
What is not established — and what STAC's authors identify explicitly as untested — is how such
controls behave against an adaptive attacker, and how they perform on the false-approval,
false-block and utility trade-off that determines whether a control is deployable in a real
service environment. This project builds the control for the Provider's environment and
evaluates it on exactly those terms.

---

# Proposed Solution

The proposed solution is a **fail-closed runtime containment monitor** positioned between the
Provider's LLM agents and the tools those agents invoke. Every tool call is intercepted before
execution and receives one of three verdicts:

- **ALLOW** — the call matches a policy rule permitting it; it proceeds to the tool.
- **DENY** — the call matches a prohibiting rule, completes a known malicious sequence, or
  matches no rule at all. It never reaches the tool.
- **GATE** — the call belongs to an irreversible, high-blast-radius class and requires human
  approval through an operator console before proceeding. No approval means denial.

The design derives from established security principles rather than from novel invention.
Anderson's reference monitor (1972) requires complete mediation, tamper-resistance and
verifiability. Saltzer and Schroeder (1975) supply fail-safe defaults and least privilege. The
most useful framing for a technical audience is by analogy: **the monitor is seccomp for tool
calls** — a narrow, independently configured layer constraining what a process may do, regardless
of what that process intends.

Four properties distinguish it from the controls reviewed above:

1. **Argument awareness.** Verdicts depend on what a call carries, not only which tool it names.
   `shell("ls")` and `shell("rm -rf /")` receive different verdicts.
2. **Fail-closed default.** A call matching no rule is denied. Policy gaps and configuration
   failures fail safe rather than open.
3. **Stateful sequence evaluation.** A kill-chain state machine tracks progress through named
   malicious sequences and blocks the chain at the step that completes it, even though every
   individual call passes per-call checks.
4. **Independence from the agent.** No verdict depends on anything the agent says. An agent
   cannot argue, assert or inject its way to an approval.

Supporting these: an append-only JSONL audit log recording every decision with a traceable rule
identifier, and a web console giving operators authenticated access to the live decision feed,
the pending-approval queue, the active policy and current sequence state.

*See Figure 3 — Proposed Solution Architecture.*

---

# Project Requirements Specification

## System Requirements

| ID | Requirement |
|---|---|
| SR-01 | The monitor shall intercept 100% of tool calls before execution; no code path shall reach a tool without a decision. |
| SR-02 | Every decision shall be ALLOW, DENY or GATE, and shall carry a traceable rule identifier. |
| SR-03 | Policy shall be expressed as declarative, version-controllable data, separate from application code. |
| SR-04 | The monitor shall evaluate sequences of calls, not only individual calls. |
| SR-05 | The monitor shall route irreversible operations to human approval. |
| SR-06 | Every decision shall be written to an append-only audit log sufficient to reconstruct a complete run. |
| SR-07 | The monitor shall be agnostic to the underlying language model and agent framework. |
| SR-08 | Decision latency shall not exceed 50 ms per call at the 95th percentile, so that mediation is imperceptible relative to model inference time. |
| SR-09 | An authenticated web console shall provide the decision feed, approval queue, policy view and sequence state. |

## Hardware and Software Requirements

**Development and evaluation hardware:** Intel Core i7-12700K, 32 GB RAM, NVIDIA RTX 4060
(8 GB VRAM), 1 TB NVMe SSD. The GPU requirement is driven by local model inference; at
4-bit quantisation both candidate models remain fully GPU-resident with context headroom.

**Production deployment:** the monitor itself is lightweight — policy evaluation is
pattern-matching and a state-machine transition. Sizing is governed by the agent's model
requirements, not the monitor's, and the monitor can run alongside the agent host.

**Software:**

| Component | Choice | Rationale |
|---|---|---|
| Language | Python 3.11+ | Ecosystem alignment with agent tooling; strong typing support |
| Agent runtime | Ollama, Llama 3.1 8B (Q4) | Local inference — no data leaves the environment |
| Policy format | YAML | Human-readable, diffable, version-controllable |
| Web console | Flask + Jinja2 | Minimal footprint; no build toolchain to maintain |
| Testing | pytest, pytest-cov | Coverage gates on security-critical modules |
| Static analysis | ruff, mypy | Lint, format and full type checking |

Local inference is a deliberate choice with a compliance dimension: no prompt, ticket content or
tool result is transmitted to a third-party model provider. This avoids creating a new business
associate relationship, which would otherwise require a BAA and expand the Provider's compliance
surface.

## Detailed Security Requirements

| ID | Requirement | Verification |
|---|---|---|
| SEC-01 | Complete mediation — no tool executes without a decision | Dispatch-layer test proving no unmediated path exists |
| SEC-02 | Fail-closed — unknown tool or unmatched call denied | Unit tests; empty-policy test denies all calls |
| SEC-03 | Argument awareness with anchored matchers resistant to encoding, traversal and look-alike evasion | Unit and fuzz tests |
| SEC-04 | Sequence-level blocking of the canonical chain while each call passes per-call checks | Unit test plus red-team scenario |
| SEC-05 | Approval gate on file delete, network send, data export, credential access; no approval means deny | Per-class tests plus timeout test |
| SEC-06 | Agent output cannot influence a verdict | Bypass-attempt test (`approved=true`, persuasive reason string) |
| SEC-07 | Audit log append-only; every record carries a non-null rule identifier | Replay test plus append-only property test |
| SEC-08 | Console requires authentication; sessions expire | Integration test plus manual verification |
| SEC-09 | No real credentials, PHI or client data in the repository or logs | Code review; argument hashing rather than plaintext logging |

**Status of two requirements in the delivered build.** SEC-08 is met: the console enforces a
30-minute idle and 8-hour absolute session limit server-side, rotates the session and a per-session
CSRF token at login, and requires that token on every approve, deny and logout POST; the expiry and
CSRF paths are covered by `tests/web/test_auth.py`. SR-06 is substantially met: alongside each
decision, the log now records tool execution outcomes (`ToolExecutionEvent`), chain progress with
named binding digests (`ChainProgressEvent`) and the resolving operator's digest, and each record is
hash-chained. It is not yet complete, because a call presented with an unknown session is denied
(`system.invalid_session`) without an audit record.

## Ethical and Professional Considerations

**Human oversight of autonomous systems.** The approval gate embodies a position: certain
consequences should not be reachable without a person accepting them. Turan (2026) constrains how
that principle can be applied — the reviewing human is finite, and a gate scoped too broadly
destroys itself through fatigue. The gate here is deliberately narrow, scoped to irreversibility
multiplied by blast radius, so that each prompt carries meaning. With three technicians, this is
a practical constraint rather than a theoretical one.

**Patient data.** All development and evaluation uses mock tools operating over in-process state.
No protected health information, no real client data and no live client system is touched at any
point. This is an ethical requirement and a practical one — the alternative would itself
constitute a HIPAA risk.

**Dual-use considerations.** The red-team scenarios describe attack chains against agent systems.
They are constructed against mock tools in an isolated environment and derived from published,
peer-reviewed academic work rather than from novel offensive research.

**Professional responsibility and honest limitations.** The monitor is a mitigation, not a
guarantee. Schneider (2000) establishes that an execution monitor can enforce safety properties
but offers no completeness guarantee — this design catches sequences it has been taught to
recognise, and cannot claim to catch those it has not. The report states that limitation plainly
rather than implying comprehensive protection. Overstating a security control's coverage to a
client is itself a professional failure, and in a HIPAA context it is one with legal weight.

**Disclosure of AI assistance.** `[CONFIRM — per the course AI usage policy, describe how AI
tools were used: literature identification and summarisation, drafting assistance, code review,
etc.]`

## Estimated Cost

Costs are expressed at the Provider's **billable client rate of $150 per hour** rather than at
internal loaded cost. This is deliberate and conservative: every hour a technician spends
building or maintaining this control is an hour not billed to a client, so the billable rate
represents the true opportunity cost to the firm. Internal loaded cost would produce a figure
roughly half this size; the larger number is used so that the justification below holds even
under the least favourable accounting.

**One-time / development**

| Item | Basis | Cost |
|---|---|---|
| Development workstation (GPU-capable) | Existing hardware, amortised | $1,800 |
| Development effort | 280 hrs @ $150/hr | $42,000 |
| Security review and testing | 32 hrs @ $150/hr | $4,800 |
| Documentation and training material | 32 hrs @ $150/hr | $4,800 |
| **One-time subtotal** | | **$53,400** |

**Recurring (annual)**

| Item | Basis | Cost |
|---|---|---|
| Software licensing | Open-source stack — Python, Flask, Ollama, Llama 3.1 | **$0** |
| Hosting / compute for agent and monitor | $100/mo | $1,200 |
| Maintenance and policy updates | 6 hrs/mo @ $150/hr | $10,800 |
| Annual security review | 12 hrs @ $150/hr | $1,800 |
| **Recurring subtotal** | | **$13,800** |

**First-year total: $67,200. Subsequent years: $13,800.**

### Cost justification

Three comparisons frame the investment.

**Against loss.** IBM's *Cost of a Data Breach Report 2026* places the average healthcare breach
at $6.64 million. HIPAA Tier 2 penalties alone carry an annual cap of $2,190,294 per violation
category. A proportionate incident at the Provider's scale would be far smaller in absolute
terms, but the first-year cost of this control is approximately **one percent of the
industry-average breach figure** and roughly **three percent of a single Tier 2 annual cap**. The
Provider does not need the control to prevent a $6.64 million loss to justify it; it needs only
to prevent one incident of any consequential size.

**Against regulatory posture.** The distinction between HIPAA Tier 1 (reasonable efforts) and
Tier 2 (lack of oversight) is, in practice, a question of what an organisation can demonstrate.
Granting an autonomous agent administrative privilege with no governing control, no policy and
no decision record is difficult to defend as reasonable effort. The same deployment behind a
documented, tested, auditable enforcement layer with a complete decision log is a materially
different position — and the difference between those tiers, at the $2.19 million annual cap, is
larger than the entire cost of this project by two orders of magnitude.

**Against opportunity.** The pilot currently saves diagnosis time and gives it straight back
in execution time, because the agent may not act. The control is what allows the agent to act,
and the threshold it must clear is modest. At the Provider's $150 billable rate, the first-year
cost of $67,200 corresponds to 448 hours of recovered technician time, and the recurring annual
cost of $13,800 corresponds to 92 hours. Across a service desk of three technicians, that is
approximately three hours per technician per week — a little over half an hour per working day
— in the first year, falling to under eight minutes per day once the one-time development cost
is retired.

Framing the return as recovered hours rather than per-ticket savings is deliberate. It avoids
resting the justification on a ticket-mix estimate, and it states the question in the form the
Provider's leadership can answer directly from experience: whether permitting the agent to
execute routine remediation, rather than only diagnose it, recovers half an hour of a
technician's day.

**Zero licensing cost is a deliberate design outcome**, not an accident. An entirely open-source
stack with local inference avoids per-seat licensing, avoids introducing a new business associate
relationship with a model provider, and leaves the Provider's compliance surface unchanged — no
new BAA, no new vendor risk assessment, no new data-flow to document.

### Limitations of available data

Operational metrics from the Provider's professional services automation platform — ticket
volume, category distribution, average handling time, and the division of handling time between
diagnosis and execution — were not available for this study. Cost and return figures are
therefore constructed from the Provider's published billable rate and from published market and
service-desk benchmarks, and are expressed as thresholds rather than forecasts: the analysis
establishes what the control must save to justify its cost, not what it is predicted to save.
Validating those thresholds against the Provider's own operational data is identified as
follow-on work in *Review and Continuous Improvement*.

---

## Draft status

| Section | Rubric pts | Status |
|---|---|---|
| Company Profile and Business Case | 5 | **Complete** |
| Problem Identification | 5 | **Complete** — all figures sourced |
| Proposed Solution and Requirements | 10 | **Complete** — 1 item outstanding (below) |

**Outstanding — yours to supply:**
1. **AI usage disclosure** (Ethical and Professional Considerations) — required by the course AI
   policy.

*Previously outstanding, now resolved:* the ROI calculation (Estimated Cost, third comparison)
was resolved on 2026-09-03 by reframing the economic analysis as recovered-technician-hour
thresholds rather than per-ticket savings — see *Limitations of available data* above and
Decision Log D19. It no longer depends on an unavailable ticket-mix estimate.
| Figure 1 — Organizational Hierarchy | — | Rendered |
| Figure 2 — Current-State Architecture | — | Rendered |
| Figure 3 — Proposed Solution Architecture | — | Rendered |

### Sources used for verified figures

- HIPAA civil monetary penalty tiers effective 28 January 2026 — HIPAA Journal, *HIPAA Violation
  Fines* <https://www.hipaajournal.com/hipaa-violation-fines/>
- Healthcare breach cost $6.64M, 13th consecutive year highest; 247-day mean time to identify and
  contain; AI-driven attacks +56% adding ~$1M — IBM *Cost of a Data Breach Report 2026* via
  Becker's Hospital Review
  <https://www.beckershospitalreview.com/healthcare-information-technology/cybersecurity/healthcare-data-breaches-cost-6-64m-on-average-report/>

*Cite these properly in APA in the final document. Prefer citing the IBM report directly if you
can obtain it.*
