# Compliance Mapping — AI-Agent Tool-Call Containment Monitor

**Issue:** [#21](https://github.com/lcolon231/MIST-Capstone/issues/21)  
**Baseline and sources reviewed:** 2026-09-14  
**Owner:** the Provider's Owner / HIPAA Security Officer

## 1. Scope and interpretation

This mapping explains how the capstone's containment monitor contributes to selected HIPAA
safeguards, NIST CSF 2.0 Govern/Protect/Detect outcomes, and ISO/IEC 27001 management-system
requirements. It is an engineering assessment of a local prototype using mock tools and synthetic
data. It does not establish organization-wide compliance or certification.

In the case study, client practices are HIPAA-covered entities. The Provider's business-associate
status and obligations depend on its actual services and handling of protected information;
record that determination and applicable agreements before introducing real electronic protected
health information (ePHI). HHS describes the Security Rule's scope and the responsibilities of
covered entities and business associates in its
[Security Rule summary](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html).

**Regulatory baseline:** this document maps the current Security Rule identified by HHS, not
proposals as if they were effective requirements. HHS's
[NPRM page](https://www.hhs.gov/hipaa/for-professionals/security/hipaa-security-rule-nprm/index.html)
states that the current rule remains in effect during rulemaking. The Security Officer should
recheck effective requirements before an operational deployment and during each annual review.

### Status legend

- **Partial:** an implemented mechanism supports part of the outcome within the prototype;
  the listed gap prevents a broader claim.
- **Planned:** this repository documents a procedure or design, but operational execution is
  not evidenced.
- **External:** fulfillment depends on the Provider/client organization or infrastructure
  beyond this application.

The mappings are the author's assessment, not an official crosswalk or an auditor's conclusion.
Source identifiers describe requirements/outcomes; the evidence and gap columns describe this
project. No row means that a complete legal standard is satisfied by one software feature.

## 2. Evidence register and implementation limits

| ID | Repository evidence | What it supports and what it does not prove |
|---|---|---|
| E1 | [Service](../src/monitor/service.py), [verdict engine](../src/monitor/verdict.py), [policy](../policies/rmm.yaml), [service tests](../tests/monitor/test_service.py) | Mock calls pass through argument-aware policy with default denial. It does not authorize real patient-data uses or secure arbitrary external tool paths. |
| E2 | [Sequence engine](../src/monitor/sequence.py), [canonical-chain tests](../tests/monitor/test_canonical_chain.py), [session registry](../src/monitor/session.py) | Modeled sequences are evaluated against live state. Cross-session/restart reconstruction is not wired; idle expiry is a no-op, and [reconstruction](../src/audit/replay.py) raises `NotImplementedError`. |
| E3 | [Gate](../src/monitor/gate.py), [console routes](../src/web/views.py), [authentication](../src/web/auth.py), [console tests](../tests/web/test_console.py) | Operator/viewer access and a waiting service's gate enforcement exist. The queue does not preserve the resolving operator; service resolution records use `operator=None`. The seeded console is separate from the launcher's monitor. |
| E4 | [Audit events](../src/audit/events.py), [writer](../src/audit/writer.py), [chain verifier](../src/audit/chain.py), [integrity tests](../tests/audit/test_chain.py) | Arguments are digested; ordinary evaluated decisions carry rule IDs. Hash verification is explicit, not part of event replay. Invalid-session/error paths are not all recorded; verdicts do not establish execution success. Tail truncation and a fully recomputed chain need independent evidence to detect. |
| E5 | [Loopback transport design](design/loopback-transport.md), [transport tests](../tests/test_loopback_transport.py) | Agent and monitor can run in separate processes. This is not a hardened tenant boundary: current loopback HTTP is unencrypted and assumes a trusted local host. |
| E6 | [Evaluation results](evaluation-results.md), [committed evidence](../results/issue-19/README.md) | Six attack and four benign scenarios supply bounded evidence. The recorded live model attempted three of six attributed harmful actions; all three were contained. This is not universal attack coverage. |
| E7 | [Maintenance plan](maintenance-plan.md), [manual](user-manual.md), [training](training.md), [FAQ](faq.md) | Operating procedures and training material exist. Staff attendance, real maintenance records, deployed monitoring, and recovery performance are not evidenced by their publication. |
| E8 | [Threat model](../threat-model.md), [residual risks](design/residual-risks.md), [decision log](../Decision%20Log.md) | Design rationale and accepted scope limits. Where design intent exceeds executable behavior, E1–E5 and the limits above govern this mapping. |

## 3. HIPAA mapping

The following tables select requirements relevant to the monitor. They do not replace the full
Privacy, Security, and Breach Notification Rules. In the current rule, an **addressable**
implementation specification still requires an appropriateness assessment and documented handling;
it is not simply optional. See the
[HHS explanation](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html).

### Administrative safeguards

Identifiers below refer to
[45 CFR §164.308](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308).

| Reference / focus | Status and project contribution | Gap, accountable owner, and evidence needed |
|---|---|---|
| §164.308(a)(1)(ii)(A)–(B): risk assessment and treatment | **Partial:** E8 analyzes agent-driven misuse; E1–E2 implement specific mitigations. | Security Officer: inventory actual ePHI flows and assess the whole environment; retain approved risks, treatment decisions, and reassessments. |
| §164.308(a)(1)(ii)(D): activity review | **Partial:** E4 provides decision records; E7 prescribes reviews. | Security Officer: demonstrate completed reviews, handle unlogged error paths, and retain findings with closure evidence. |
| §164.308(a)(2), (a)(3), (a)(4): responsibility and access governance | **Partial / External:** E3 separates viewer and operator powers; E7 assigns proposed duties. | Owner and Service Manager: appoint named owners; implement joiner/mover/leaver access reviews and client-specific authorization. Shared demo accounts do not identify individual staff. |
| §164.308(a)(5): workforce preparation | **Planned:** E7 provides onboarding and refreshers. | Service Manager: retain attendance and exercise outcomes, and address unsuccessful completion before approval duties. |
| §164.308(a)(6): incident handling | **Planned:** E7 defines triage and escalation; E4 can supply evidence. | Security Officer: establish and exercise the broader incident procedure, including impact assessment and client coordination. A denied attempt alone is not proof of a reportable breach. |
| §164.308(a)(7): contingency arrangements | **Planned / External:** E7 specifies backup and restore exercises. | Infrastructure Lead: demonstrate backups, recovery, and emergency operations; live sequence-state recovery remains unimplemented. |
| §164.308(a)(8): periodic evaluation | **Partial:** E6 supplies synthetic technical evaluation; E7 schedules review. | Security Officer: add nontechnical and deployment-specific evaluation and repeat it when risks or environments change. |

### Technical safeguards

Identifiers below refer to
[45 CFR §164.312](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312).

| Reference / focus | Status and project contribution | Gap, accountable owner, and evidence needed |
|---|---|---|
| §164.312(a)(1), (a)(2)(i): authorized access and unique identity | **Partial:** E1 restricts tool actions; E3 checks console roles and passwords. | Infrastructure Lead: individual accounts, tenant isolation, authorization reviews, and durable attribution of approvals to the actual human. A monitor session token is not a staff identity. |
| §164.312(a)(2)(ii)–(iii): emergency access and idle logoff | **Partial:** E3 enforces a 30-minute idle logoff and an 8-hour absolute session limit server-side, plus manual logout; there is no tested emergency-access process. | Service Manager: define authorized manual continuity; Infrastructure Lead: confirm the timeout values against policy. Sequence idle-expiry settings are not console logout controls. |
| §164.312(a)(2)(iv), (e): stored/transmitted data protection | **External:** E5 uses local plaintext HTTP; logs and configuration are not encrypted by this app. | Infrastructure Lead: assess encryption, key handling, protected transport, and host storage; retain decisions and configuration tests. A digest is not encryption. |
| §164.312(b): audit mechanisms | **Partial:** E4 records decisions and gated resolutions on the service path. | Security Officer: complete actor/error/outcome coverage, independent preservation, review, and access controls. Record count and an intact local chain alone cannot prove completeness. |
| §164.312(c)(1)–(2): record integrity | **Partial:** E1 gates mock deletes; E4 detects inconsistent audit-chain links. | Infrastructure Lead: validate integrity of the actual clinical data systems. Protecting monitor logs does not authenticate ePHI records. |
| §164.312(d): authentication | **Partial:** E3 hashes passwords, rejects invalid console credentials, rotates the session and its CSRF token at login, and requires that token on every approve/deny/logout. | Infrastructure Lead: replace demo identities, add authentication monitoring, and assess stronger (multi-factor) authentication for actual deployment. |

### Organizational, physical, and documentation obligations

| Reference / focus | Status and boundary | Required follow-through |
|---|---|---|
| [§164.308(b)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.308): business-associate arrangements | **External:** an `approved-baa-backup` mock destination is a fixture name; it is not evidence of a signed business associate agreement (BAA). | Client Success and Security Officer: verify recipient identity, permitted purposes, contracts, and subcontractor handling before enabling real exports. |
| [§164.310](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.310): physical safeguards | **External:** application code does not secure facilities, endpoints, or media. | Infrastructure Lead: document physical access, workstation protection, media handling, and disposal for actual hosts. |
| [§164.316](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.316): controlled documentation | **Planned:** E7 and E8 provide draft procedures and rationale. | Security Officer: approve, make available, review, and retain required documentation for six years from creation or last effective date, whichever is later. Set a separate risk-based runtime-log schedule; do not equate all logs with required policy documentation. |

The Security Officer must also assess applicable Privacy Rule use/disclosure restrictions and
Breach Notification duties with the client. The monitor cannot decide legal disclosure authority
from an operator click or a destination label. HHS distinguishes these rules in its
[Security Rule summary](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html).

## 4. NIST CSF 2.0 — Govern, Protect, Detect

CSF 2.0 describes cybersecurity outcomes rather than prescribing this implementation. The selected
identifiers below come from Appendix A of
[NIST CSWP 29](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf).
The project-specific contributions and gaps are an author-created mapping. A full organizational
profile would also address Identify, Respond, and Recover.

| Function / selected outcome | Status and evidence | Remaining action / owner |
|---|---|---|
| Govern — GV.OC-03: obligations | **Planned:** this mapping and E8 identify relevant concerns. | Security Officer: validate client, contractual, and regulatory requirements for the actual service. |
| Govern — GV.RR-02: assigned authority | **Planned:** E7 identifies maintenance and incident owners. | Owner: name primary/backup staff and record delegated authority and coverage. |
| Govern — GV.PO-01, GV.PO-02: policy lifecycle | **Partial:** E1 enforces YAML rules; E7 prescribes reviewed changes. | Service Manager: evidence approval, communication, and periodic review of both organizational policies and tool rules. |
| Govern — GV.OV-01: review of risk results | **Partial:** E6 supplies bounded evaluation; E7 defines management review. | Security Officer: retain actual review decisions, priorities, and follow-up outcomes. |
| Protect — PR.AA-05: least privilege | **Partial:** E1 and E3 restrict calls and approval actions. | Infrastructure Lead: harden identity, sessions, tenant boundaries, and real tool access. |
| Protect — PR.AT-02: specialist preparation | **Planned:** E7 gives operators practical exercises. | Service Manager: assess competence before approval access and retain refresher results. |
| Protect — PR.PS-01, PR.PS-02: configuration and software upkeep | **Planned:** E7 specifies inventory, patching, review, and rollback. | Infrastructure Lead: produce release manifests, patch records, and exception reviews. |
| Protect — PR.PS-04: usable logs | **Partial:** E4 emits decision records. | Infrastructure Lead: complete missing event coverage and deploy protected collection; no Prometheus integration is currently shipped. |
| Protect — PR.DS-11: recoverable backups | **Planned:** E7 specifies preservation and restore tests. | Backup Engineer: prove restoration and address unsupported sequence-state recovery. |
| Detect — DE.CM-09: runtime observation | **Partial:** E1–E2 examine proposed tool actions. | Infrastructure Lead: add availability/error telemetry and trusted monitoring of the underlying host; limit claims to modeled chains. |
| Detect — DE.AE-02: event interpretation | **Partial:** rule IDs and E6 help explain observed decisions. | Tier 2: correlate with trusted workflow context; preserve evidence without raw patient data in tickets. |
| Detect — DE.AE-08: incident thresholds | **Planned:** E7 defines security escalation triggers. | Security Officer: exercise incident classification and record decisions; a high deny rate is not automatically an incident. |

Prometheus and Grafana are proposed ways to support visibility in this project. Their installation
alone would not demonstrate achievement of these outcomes; collectors, ownership, response, and
tested failure handling are also needed. See [maintenance plan §4](maintenance-plan.md#4-monitoring-and-performance).

## 5. ISO/IEC 27001:2022 mapping

ISO/IEC 27001 addresses an information security management system (ISMS), including ongoing risk
management and improvement. The current catalog lists the 2022 edition and its 2024 amendment.
See [ISO's standard overview](https://www.iso.org/standard/27001) and
[Amendment 1:2024](https://www.iso.org/standard/88435.html).

This is a **selected clause-level contribution map**, not an Annex A checklist or a Statement of
Applicability. Clause numbering was checked against the
[ISO/IEC 27001:2022 preview](https://gso-sims-preview-doc-aws.s3-eu-west-1.amazonaws.com/iso-iec-27001-2022-en.html).
The short focus labels below are paraphrases. Detailed conformance assessment requires the
applicable standard and the Provider's complete ISMS scope and evidence.

| Clause / focus | Status and project contribution | Gap and owner |
|---|---|---|
| 4.3: scope | **Partial:** E8 states the agent/tool boundary and mock environment. | Owner: define the organization's actual ISMS scope, services, sites, parties, and dependencies. |
| 5.3: responsibilities | **Planned:** E7 assigns operating duties. | Owner: formally assign authority and resources across the service. |
| 6.1.2–6.1.3: risk assessment and treatment | **Partial:** E8 identifies threats; E1–E5 provide bounded technical treatments. | Security Officer: maintain an approved organizational risk process and treatment record, including residual-risk decisions and a Statement of Applicability. |
| 7.2–7.3: staff capability | **Planned:** E7 contains practical training. | Service Manager: retain competence and awareness evidence, including retraining outcomes. |
| 7.5: document control | **Partial:** versioned policies and operating documents are available. | Security Officer: control approval, access, retention, and revision history for operational records as well as source files. |
| 8.1: managed operation | **Partial:** E1 deterministically checks mock calls; E7 defines change procedures. | Infrastructure Lead: evidence deployed changes and supplier controls, and close the prototype integration gaps. |
| 9.1: measurement | **Partial:** E6 provides reproducible, limited evaluation. | Service Manager: define operational measures and owners; validate proposed monitoring and avoid overstating the live attack results. |
| 9.2–9.3: audit and management evaluation | **Planned:** E7 schedules sampling and management review. | Owner: demonstrate independent audits, recorded review decisions, and completed actions. |
| 10.1–10.2: improvement and correction | **Planned:** E7 routes findings into reviewed fixes and retests. | Service Manager: retain defect/root-cause records and evidence that corrective actions worked. |

Before making a conformance claim, review the complete standard and amendment, applicable
Annex A controls, and all requirements within scope. The monitor's code and tests alone do not
establish an operating ISMS or certification. ISO describes certification separately from using
the standard in its [overview](https://www.iso.org/standard/27001).

## 6. Prioritized gaps and review procedure

The following are follow-up acceptance conditions for operational use, not features delivered by
issue #21:

| Priority / owner | Action | Completion evidence |
|---|---|---|
| Before real workloads — Infrastructure Lead | Implement durable sequence reconstruction and test restarts/session changes; preserve history through retention and archival changes. | End-to-end tests that an interrupted modeled chain still blocks after restart. |
| Before operational approvals — Infrastructure Lead | Connect the console to the actual service; persist authenticated operator attribution and execution/error outcomes. | One correlated call, gate, actor, resolution, and outcome record; integration tests for approve, deny, timeout, and failures. |
| Before non-demo access — Infrastructure Lead | Harden authentication, CSRF/session controls, service hosting, host permissions, and protected transport; validate client isolation. | Reviewed configuration and positive/negative access tests. |
| Before handling ePHI — Security Officer and Client Success | Complete risk analysis, data/recipient inventory, agreement review, physical safeguards, and incident/continuity procedures. | Approved organizational records and exercised procedures. |
| Before relying on evidence durability — Backup Engineer | Establish protected independent copies/head records, retention, and tested recovery; address logs missing events and unauthenticated chain rewrites. | Restore and tamper/completeness tests against separately protected evidence. |
| Before relying on automated monitoring — Infrastructure Lead | Implement the proposed collector, dashboards, alert routes, and freshness/error signals. | Synthetic failures reach the assigned responder; outages and missing telemetry are visible. |
| Quarterly and after material change — Security Officer | Recheck this mapping against source behavior, deployed evidence, framework revisions, audit findings, and client obligations. | Dated review with status changes, owners, due dates, and verified closures. |

At each review, retain the assessed Git revision, release/configuration manifest, test artifacts,
and the date of the external-source check. Move a row from Planned to Partial only when operating
evidence supports it. Keep unresolved gaps explicit in the report and link corrective work through
the [maintenance feedback process](maintenance-plan.md#7-refresher-training-and-feedback-loop).
