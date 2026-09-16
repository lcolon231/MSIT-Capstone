# Review and Continuous Improvement

## Purpose and Scope

The containment monitor requires regular review to remain effective. Its performance depends on the continued accuracy of its policy rules, sequence definitions, approval procedures, audit evidence, and operating assumptions. Changes to the agent model, tool inventory, Provider workflows, or threat landscape can make a previously acceptable rule too permissive, too restrictive, or incomplete. The review process combines operational evidence, security findings, user feedback, regression testing, and business results in a documented improvement cycle.

The current implementation is a local prototype that uses mock tools and synthetic records. The cadence and responsibilities described in this section are proposed procedures for a Provider pilot. They should not be presented as evidence that production monitoring, staffing, or automated alerting has already been deployed. Before the monitor handles real client work, the Provider must connect the console to the active enforcement process, complete approval-actor attribution, improve error and execution-outcome telemetry, and validate restoration of sequence state across restarts.

## Review Ownership and Cadence

The Provider's Owner, acting as HIPAA Security Officer, is accountable for risk acceptance and the decision to suspend or resume automation after a security failure. The Service Manager owns the operating review, assigns corrective work, and confirms that operators are available. The Infrastructure Lead maintains the host, dependencies, model runtime, audit storage, and monitoring configuration. Operators identify workflow problems and suspected false decisions, while a designated maintainer reproduces defects and prepares reviewed changes. A reviewer other than the change author should assess security-sensitive policy or code changes before acceptance.

The review cadence should match the speed at which evidence is produced and risk can change.

| Cadence or trigger | Review activity | Required record |
|---|---|---|
| Before and after each prototype or pilot run | Confirm the intended policy, transport, audit destination, disk capacity, and run identifier. Verify the completed audit chain and preserve the result. | Run checklist, configuration revision, verifier output, and evidence location. |
| Each operating day | Inspect decisions, pending approvals, timeouts, failures, log growth, and outstanding security tickets during active use. | Daily review record and escalated tickets. |
| Weekly | Review DENY and GATE patterns, default-deny calls, suspected false blocks, unusual repetition, dependency advisories, and unresolved findings. | Review notes with owner, priority, and due date for each action. |
| Monthly | Review policy and tool inventory, approval classes, access roster, storage growth, operational thresholds, and accepted exceptions. | Approved change list, exception register, and rollback evidence. |
| Quarterly | Sample audit evidence, test restoration in isolation, review access rights and residual risks, and deliver operator refresher training. | Audit sample, restore report, training record, and corrective-action status. |
| Annually or after a material change | Reassess the threat model, client obligations, recovery targets, staffing, costs, and the continuing suitability of the control. Conduct an incident tabletop. | Risk review, funded improvement plan, and management decision. |
| After an incident, suspected bypass, new tool, policy change, model change, transport change, or security fix | Perform a focused review immediately and rerun affected checks before returning the workflow to service. | Incident or change ticket, regression evidence, approval, and post-change observation. |

An actively exploited vulnerability, audit-write failure, suspected containment bypass, or unexplained harmful execution should trigger immediate suspension of the affected automation. The Security Officer should authorize resumption only after the condition is understood, corrective controls are tested, and remaining risk is recorded.

## Audit Findings as the Improvement Input

The audit log is the primary technical input to continuous improvement because it connects each evaluated call to its verdict, rule identifier, session, principal, and argument hash. Approval resolutions and sequence progress provide additional context. The hash chain can expose inconsistent edits, deletions, or reordering within a preserved file when the verifier is run. It does not prove that the log is complete, prevent an attacker from recomputing an unkeyed chain, or detect every removed suffix without an independent checkpoint. Reviewers must therefore combine chain verification with protected copies, file manifests, process observations, and related ticket evidence.

A quarterly audit sample should include at least one ALLOW, one DENY, one gated denial or timeout, one approved synthetic operation, one patch or change ticket, one restore result, and one operator training record. The reviewer should confirm that the rule identifier explains the decision, the relevant software and policy revisions can be identified, and the recorded outcome supports the claim being made. A GATE decision or approval record alone does not prove that a tool executed successfully. Missing actor attribution, absent error-path events, unexplained gaps, or a mismatch between the audit log and other observations should become findings rather than being treated as harmless documentation defects.

Findings should be classified by operational effect. A false approval, containment bypass, or audit-integrity failure is a security finding. A legitimate action incorrectly denied is a false-block or utility finding. Repeated default-deny decisions can indicate an unknown tool, malformed proposal, or policy drift. Approval timeouts may reflect intended fail-closed behavior, inadequate staffing, or an unrealistic timeout. Repeated model calls may remain fully mediated while revealing poor task termination or wasted capacity. This classification prevents all DENY and GATE activity from being interpreted as either an attack or proof that the control worked correctly.

Each finding should record its severity, source evidence, affected release and policy, expected and actual behavior, owner, due date, proposed correction, retest result, and closure decision. Tickets must reference restricted evidence rather than copying protected health information, credentials, raw prompts, or unreviewed logs into a general helpdesk system.

## Feedback and Corrective-Action Cycle

Audit and operator findings feed back into the system through a controlled seven-step cycle:

1. **Observe and preserve.** Record the run, configuration, rule identifier, symptom, and relevant evidence. Verify and copy the closed log before making changes.
2. **Classify and prioritize.** Determine whether the event represents an attack attempt, false approval, false block, approval-process problem, model behavior problem, operational failure, or documentation gap. Assign an owner and response target.
3. **Reproduce safely.** Reproduce the behavior with synthetic data in an isolated environment. If the behavior cannot be reproduced, retain the finding as unresolved and identify the additional telemetry needed.
4. **Convert the finding into a regression case.** Add or update a scenario or focused test that fails for the observed behavior. New attack cases should identify the attributed harmful action so that a model non-attempt is not counted as monitor containment. A legitimate workflow that was blocked should become a benign utility case.
5. **Correct the narrow cause.** Update the relevant policy predicate, sequence definition, approval rule, transport behavior, operational procedure, or documentation. A correction must not weaken unrelated denials or remove a difficult scenario merely to make the evaluation pass.
6. **Verify and approve.** Run focused tests, the complete deterministic suite, linting, formatting, and type checks. Repeat live-model evaluation when the model or its interface changes. Another reviewer should inspect security-sensitive changes, and the Service Manager should approve the release and rollback criteria.
7. **Deploy and observe.** Apply the reviewed change during a controlled window, use a fresh audit path, run synthetic smoke tests, and watch the next operating period for recurrence or new false decisions. Close the finding only after the recorded evidence shows that the correction works.

The regression suite preserves the results of this process. Without a test or scenario, the same weakness can return during a later policy, model, or transport change. The deterministic suite provides the stable acceptance baseline. Live-model runs add evidence about whether model behavior continues to exercise the relevant paths.

## Measures Used in Review

The Provider should review security, utility, and operational measures together. The saved evaluation already reports containment, false-approval, false-block, utility, attack-attempt, and monitor-containment rates. The distinction between attack-attempt rate and monitor-containment rate is essential. In the five recorded live-model runs at temperature 0.8, the model proposed the attributed harmful action in three of six attack scenarios per run, and the monitor contained all three attempts. The remaining attacks were not monitor blocks because the model never proposed the attributed harmful action. Future reports should preserve both denominators.

The existing results provide a baseline for the evaluated scenarios. The deterministic run exercised all six harmful actions, while five live runs sampled one local 8B model. Additional evaluation is required when tools, prompts, model builds, quantization, policies, or production workflows change. Reviewers should compare new results with the saved baseline and investigate unexplained changes before approving the updated configuration.

Operational review should also measure pending approval count and age, timeout count, decisions by verdict and bounded rule identifier, default-deny frequency, audit-write and chain-verification failures, disk use, and evaluation latency. These signals are proposed until instrumentation is implemented and baselined. Thresholds should be tested with synthetic failures and representative workload data before the Provider relies on them for automated alerting. Arguments, prompts, patient data, secrets, principals, destinations, and per-session identifiers should not be placed in metric labels or alert text.

## Validating Cost and Operational Value

Continuous improvement must determine whether the control provides enough operational value to justify its cost as well as whether it contains the tested threats. The current economic analysis uses recovered-technician-hour thresholds because the Provider's professional services automation data was unavailable. At a billable rate of $150 per hour, the estimated first-year cost of $67,200 requires 448 recovered technician hours. The estimated recurring annual cost of $13,800 requires 92 hours. Across three service-desk technicians, the first-year threshold is approximately three hours per technician per week, falling to less than eight minutes per technician per working day after the one-time development cost is retired.

During a pilot, the Service Manager should validate these thresholds with actual professional services automation data. The baseline should include ticket volume by category, average handling time, the share of time spent on diagnosis and execution, rework, escalations, and the number of tickets suitable for monitored automation. Pilot measurements should add operator approval time, false-block handling, exception work, maintenance effort, training time, incidents, and time saved on successfully completed tasks. The analysis should compare like periods and categories and should report the range of observed results rather than converting a short pilot into an annual forecast without qualification.

The control should advance only if it meets both conditions: it maintains an acceptable security and utility profile, and it recovers enough technician time or risk-adjusted value to justify its operating burden. Failure to reach the financial threshold does not justify weakening enforcement. The appropriate response may be to narrow the automated workflow, improve approval routing, correct excessive false blocks, or stop the pilot.

## Improvement Priorities

The first improvement priority is to close the gaps that prevent the prototype from supporting reliable operations. The console must share the active monitor's approval queue and sequence state; approval records must retain the acting operator; error paths and tool outcomes need complete audit coverage; and sequence state must be reconstructed and tested across restart or explicitly treated as non-durable. Audit verification should become part of replay or the operating workflow, with protected external evidence capable of detecting replacement or tail truncation.

After those foundations are verified, the Provider can add tested monitoring and storage automation, establish representative performance baselines, broaden benign and attack scenarios from actual approved workflows, and evaluate scoped credentials for production tools. New controls should enter the same feedback cycle and should remain disabled until their telemetry, failure behavior, and rollback procedure have been tested.

Continuous improvement uses evidence to keep the boundary between permitted, prohibited, and human-approved actions aligned with the Provider's risk, obligations, and operating reality. Review results may support expanding automation, restricting a workflow when risk increases, or suspending the system when the evidence is incomplete.

---

## Author Verification Notes — Exclude from Final Report

| Major claim | Repository evidence |
|---|---|
| Roles, maintenance cadence, audit sample, escalation, and change process | `docs/maintenance-plan.md` |
| HIPAA, NIST CSF 2.0, and ISO/IEC 27001 relationships | `docs/compliance-mapping.md` |
| Current prototype limitations | `docs/maintenance-plan.md`; `src/web/run.py`; `src/monitor/service.py`; `src/monitor/session.py`; `src/audit/replay.py` |
| Evaluation measures and five-seed results | `docs/evaluation-results.md`; `results/issue-19/attribution/multiseed/seed-1` through `seed-5` |
| Attempt-rate reporting decision | `Decision Log.md`, D20 |
| Recovered-hour thresholds and unavailable PSA data | `report/phase1-chapters.md`; `Decision Log.md`, D19 |

Before final submission, remove this verification section, reconcile the chapter number with the assembled report, and confirm that any statement about completed operational processes remains framed as a proposal unless later implementation evidence exists.
