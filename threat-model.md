# Threat Model — AI-Agent Containment Monitor

> Drafted 2026-08-23 following D9's closure (indirect prompt injection) and the instructor's
> direction to define the threat model in week one. Report placement: **Design and Development
> → Security Design Documentation**, immediately before the architecture section, because every
> design choice that follows is derived from it. Pairs with Diagram #8 (deployment / trust
> boundaries) and D11 (process placement).

---

## 1. Purpose and scope of this model

This model defines who the adversary is, what that adversary can and cannot do, what the
monitor is trusted to protect, and what it does not protect. It is stated before the design
because a containment control is only meaningful relative to an adversary — a monitor that
blocks everything defeats every attacker and is useless, so the value of the design is entirely
a function of the boundary drawn here.

The model is deliberately narrow. Where a capability is excluded, it is excluded explicitly and
the consequence is stated, rather than being left as an unexamined assumption.

---

## 2. The system under consideration

The Provider operates an LLM agent that performs routine IT operations on behalf of its
technicians: reading tickets, correlating monitoring alerts, and — in the proposed extension —
executing remediations through tool calls. The agent ingests content it does not control and
emits tool calls that have real effect on systems holding protected health information.

Four components, with distinct trust levels:

| Component | Trust | Rationale |
|---|---|---|
| **Operator / technician** | Trusted | Authenticated Provider staff. Their instruction to the agent is assumed benign. |
| **Policy (YAML) and monitor code** | Trusted | Version-controlled, human-authored, reviewed. The root of the control. |
| **Agent (model + loop)** | **Untrusted** | Non-deterministic; per Zverev et al. cannot reliably separate instructions from data. Its outputs, including any justification it offers, are attacker-influenceable. |
| **Ingested content and tool results** | **Untrusted** | Ticket bodies, forwarded email, log lines, filenames, and the return values of tools. Written by parties outside the Provider's control. |

The critical line is between rows two and three. The agent is inside the system but outside the
trust boundary. This is the whole architecture in one sentence.

---

## 3. Adversary definition

**The adversary is an external party who can place content into the data the agent reads, and
who cannot otherwise touch the Provider's infrastructure.**

Concretely, for the Provider: anyone who can cause text to appear in a support ticket, an email
forwarded into the queue, a monitored log line, or a filename on a managed endpoint. Client
staff submit tickets by design, so this surface is open by construction and cannot be closed
without removing the agent's reason to exist.

### 3.1 Adversary capabilities (what is assumed possible)

| ID | Capability |
|---|---|
| AC-1 | Insert arbitrary text into any content the agent ingests, including instructions crafted to read as directives. |
| AC-2 | Control the *return value* of a tool the agent legitimately calls, where that value derives from attacker-influenced data (a ticket body read back, a log excerpt, a directory listing containing an attacker-chosen filename). |
| AC-3 | Attempt to induce the agent to emit any tool call in the agent's registered tool set, with any arguments. |
| AC-4 | Distribute an attack across many turns and many individually innocuous tool calls, rather than requesting harm in a single step. |
| AC-5 | Know the system's design, including the policy structure and the fact that a monitor exists — Kerckhoffs applies; secrecy of the policy is not a control. |
| AC-6 | Adapt across attempts, observing which calls are refused and re-planning against the observed refusals. |

AC-4 and AC-6 are the two that most designs omit and that this project exists to test. AC-4 is
the STAC attack class; AC-6 is the adaptive attacker STAC's own authors identify as untested
against guardrails of this kind.

### 3.2 Adversary limitations (what is assumed impossible)

| ID | Limitation | Why the assumption is reasonable |
|---|---|---|
| AL-1 | Cannot modify the model weights, the system prompt, or the agent's code. | These are Provider-controlled artifacts under change management. |
| AL-2 | Cannot read or write the policy YAML, the monitor's code, or its state. | Enforced structurally by D11's process boundary, not by convention. |
| AL-3 | Cannot authenticate to the operator console or hold valid operator credentials. | Distinct threat — see §4. |
| AL-4 | Cannot execute code on the monitor host outside the agent's tool interface. | Host compromise is a prior and larger failure; the monitor assumes an intact host. |
| AL-5 | Cannot observe or tamper with the audit log. | Append-only, written by the monitor process, outside the agent's reach. |

Each limitation is a place where the design can be attacked in review, which is why they are
numbered. AL-2 in particular is only true if D11 is implemented as a genuine process boundary;
if the monitor is degraded to in-process under the scope-cut plan, **AL-2 becomes an assumption
rather than a property, and the report must say so**.

---

## 4. Explicitly out of scope

Naming these is not a weakness of the model — an unstated exclusion is the weakness.

- **A malicious or compromised operator.** The instructor's distinction is exactly this: a
  prompt-injected agent is a different adversary from a user deliberately abusing the agent.
  This project defends the former. A trusted operator instructing the agent to do harm is
  authorised action, and the monitor's response to it is the audit log, not prevention.
  *(This is the boundary STAC's published attacks sit on the far side of — hence "adapted from
  STAC", not STAC as published. See D9.)*
- **Compromise of the RMM platform itself**, independent of the agent. Pre-existing risk with
  pre-existing controls (MFA, TLS, role-based permissions).
- **Model supply-chain compromise** — a backdoored open-weight model. Mitigated in part by the
  monitor's independence: a backdoored agent still cannot execute an unpermitted call, though
  it could still exhaust the permitted action space.
- **Host and infrastructure compromise**, container escape, and side channels.
- **Denial of service** against the agent or monitor. A monitor that fails closed under load
  denies service by design; availability is not a security goal here.
- **Attacks on the agent's text output** rather than its actions — a misleading ticket summary
  shown to a technician. Progent scopes this out for the same reason; the monitor constrains
  actions, not prose.

---

## 5. Assets and attacker objectives

**Assets:** protected health information on managed endpoints; the integrity of client systems;
the RMM platform's reach across thirty practices; the audit record itself.

**Objectives an attacker would pursue, in the Provider's environment:**

1. **Exfiltration** — read PHI and transmit it outside the environment. The chained form:
   enumerate a directory → read a record → send it, each call individually within remit.
2. **Destruction** — delete or encrypt data on a managed endpoint.
3. **Persistence / privilege extension** — create an account, install a tool, alter a monitoring
   policy so future actions go unobserved.
4. **Lateral movement** — use the agent's cross-client reach to act on a second practice.
5. **Evasion** — cause a harmful action to be recorded as permitted, or not recorded at all.

Objective 5 is why auditability is a security requirement and not merely an operational one.

---

## 6. Attack surface

| Surface | Vector | Primary control |
|---|---|---|
| Ingested content (ticket, email, log, filename) | Direct instruction injection into the agent's context | Monitor is independent of agent reasoning (SEC-06) |
| Tool return values | Indirect injection arriving *after* the task is underway | Same; plus a dedicated red-team scenario (T5.2) |
| Tool arguments | Legitimate tool, harmful argument; encoding, traversal, look-alike evasion | Argument-aware anchored matching (SEC-03) |
| Tool sequence | Individually permitted calls composing into harm | Sequence state machine (SEC-04) |
| Approval path | Persuading or forging approval | Gate is fail-closed; agent output cannot flip GATE→ALLOW (SEC-05, SEC-06) |
| Monitor state | Resetting or smearing sequence state to escape detection | D12 retention policy — **open** |
| Monitor placement | Reaching the policy object or tools directly | D11 process boundary (AL-2) |

The last two rows are open design questions, which is the honest position to be in during week
one and the reason both are tracked as decisions.

---

## 7. Security goals

The monitor shall ensure that, for any agent behaviour reachable under the capabilities in §3.1:

- **G1 — Mediation.** No tool executes without a decision.
- **G2 — Fail-closed.** Absence of an explicit permission is denial.
- **G3 — Independence.** No verdict is a function of agent-produced text.
- **G4 — Sequence awareness.** A modelled malicious chain is denied at the step that completes
  it, even where every constituent call is individually permitted.
- **G5 — Reviewability.** Irreversible, high-blast-radius actions require a human decision.
- **G6 — Accountability.** Every decision is reconstructible after the fact, with the rule that
  produced it.

## 8. What the model does not guarantee

Schneider (2000) establishes that an execution monitor enforces safety properties — "nothing bad
happens" — and cannot enforce liveness. Three consequences, to be stated in the report rather
than discovered by a reviewer:

1. **No completeness for sequences.** The automaton recognises chains it has been taught. A
   novel chain of permitted calls will pass. This is a property of the mechanism, not a defect
   of the implementation, and it is why the evaluation reports false approval rather than
   claiming prevention.
2. **The permitted action space is still an action space.** An attacker confined to it can still
   cause harm proportionate to what the Provider chose to permit. Policy quality is a control,
   and a policy is a human artifact.
3. **False blocking is a real cost.** A monitor that denies legitimate work will be switched
   off, at which point its security value is zero. Utility is therefore measured as a security
   property, not as a usability nicety.

## 9. Residual risk

After the controls in §6, the Provider retains: risk from a compromised operator account; risk
from novel unmodelled chains; risk proportional to the breadth of the authored policy; and risk
that a fatigued reviewer approves a GATE without scrutiny (Turan 2026 — the reason the gate is
scoped to four classes rather than applied broadly). These are accepted, documented, and
revisited on the review cadence defined in the maintenance plan.
