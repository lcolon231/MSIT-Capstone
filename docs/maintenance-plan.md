# Maintenance Plan — AI-Agent Tool-Call Containment Monitor

**Issue:** [#21](https://github.com/lcolon231/MIST-Capstone/issues/21)  
**Baseline reviewed:** 2026-09-14  
**Accountable owner:** the Provider's Owner / HIPAA Security Officer  
**Operational owner:** Service Manager, supported by the Infrastructure Lead

## 1. Purpose and operating boundary

This plan keeps the containment monitor's policy, approval gate, audit evidence, and supporting
host maintainable throughout the case study. It covers patching, performance monitoring,
security audits, helpdesk support, refresher training, and improvement. The
[compliance mapping](compliance-mapping.md) connects these activities to selected HIPAA,
NIST CSF 2.0, and ISO/IEC 27001 requirements and outcomes.

The current implementation is a **local prototype with mock tools and synthetic records**.
The schedules and response targets below are proposed Provider operating procedures; they are
not evidence that a staffed service, monitoring deployment, or production compliance program
already exists. The intervals are local planning targets, not statutory deadlines.

### What is available today

- Argument-aware policy, modeled sequence detection, and approval gating are composed in
  [`MonitorService`](../src/monitor/service.py). The four implemented gate classes are data
  export, file delete, network send, and credential access.
- The [console](../src/web/views.py) provides authenticated views and operator/viewer roles.
  `python -m src.web.run` starts a **seeded demonstration**. For live operation,
  `python -m src.monitor_server --console-port 5000` (with `OP_PASS` set) serves the console from
  the monitor process itself, on the same approval queue the loopback endpoint blocks on.
- [JSONL audit writing](../src/audit/writer.py), [event replay](../src/audit/replay.py), and an
  [offline hash-chain verifier](../src/audit/chain.py) support inspection of recorded activity.
- The [evaluation package](evaluation-results.md) supplies repeatable synthetic scenarios and
  recorded results. Its metrics describe those scenarios, not all possible attacks.

### Limits that affect maintenance

Use executable behavior as the baseline where earlier design documents describe future work:

| Area | Current limitation | Required operational treatment |
|---|---|---|
| Restart and sequence history | `reconstruct_sequence_state` raises `NotImplementedError`; `SessionRegistry.state_for` returns live memory, and idle expiry is a no-op. Retention settings do not establish durable cross-session enforcement. | Stop task intake before maintenance. Treat restarted tasks as fresh executions requiring review; do not claim that restoring the log restores sequence state. Durable reconstruction needs implementation and restart tests before real workloads. |
| Approval evidence | The queue does not retain the operator name passed to `resolve`; the service writes `operator=None`. The demo console resolves its seeded queue without a waiting service to write a resolution event. | Retain a separate authorized operator's ticket record for demonstrations. Durable actor attribution and a console connected to the actual monitor are prerequisites for operational approvals. |
| Audit completeness | Ordinary evaluated calls are logged, but invalid-session returns and some error paths have no audit event. A verdict or approval record does not prove successful tool execution. | Investigate missing evidence using trusted process observations; complete error and execution-outcome telemetry before production use. |
| Audit integrity | Replay parses events without verifying the hash chain. The chain detects inconsistent links, but cannot authenticate a wholly rewritten chain or detect a removed suffix on its own. | Run the verifier explicitly; protect files with host permissions and preserve independent copies/head records. An intact chain alone is insufficient proof of completeness. |
| Monitoring and storage | No Prometheus exporter, Grafana dashboard, automatic rotation, archival service, or independent head sealing is shipped. | Use the manual checks below now. Implement and validate the proposed integrations before relying on automated alerts or retention. |

## 2. Responsibilities

Roles follow the [case-study organization](diagrams/01-org-hierarchy.mmd). The Service Manager
assigns a named primary and backup for each duty before an operational pilot.

| Role | Responsibility | Record retained |
|---|---|---|
| Owner / HIPAA Security Officer | Own risk acceptance, compliance review, incident classification, and authorization to resume after a security failure. | Risk decisions, review minutes, incident decisions. |
| Service Manager | Own maintenance windows, helpdesk priorities, operator coverage, and change acceptance. | Change calendar, tickets, release acceptance. |
| Infrastructure Lead / RMM Platform Engineer | Inventory versions, evaluate patches, maintain host permissions and monitoring, test upgrades and rollback. | Version manifest, test output, monitoring checks. |
| Backup & DR Engineer | Preserve evidence copies and test restoration in isolation. | Backup manifest, integrity results, restore report. |
| Tier 1 Helpdesk / operators | Review decisions and pending work during active runs, record symptoms, escalate, and complete training. | Triage record and training completion. |
| Tier 2 / designated maintainer | Reproduce defects with synthetic data and prepare reviewed fixes. | Linked issue, change diff, regression evidence. |
| Client Success & Compliance | Maintain client obligations and controlled documentation with the Security Officer. | Agreement register and document revision history. |

## 3. Maintenance and patch schedule

| Cadence / trigger | Work | Owner and completion evidence |
|---|---|---|
| Before and after each prototype run | Confirm intended policy and transport, writable audit destination, available disk space, and separate output directory. Verify the completed log. | Operator: run ID, configuration, verifier output. |
| Each operating day | Inspect decision and approval queues during active work; review failures, log growth, disk capacity, and outstanding security tickets. A quiet log during idle time is not itself an outage. | Helpdesk: daily checklist and escalations. |
| Weekly | Review security advisories for Python, Flask/Werkzeug, PyYAML, Ollama/model tooling, OS, GPU driver, and development dependencies; reconcile installed versions against the release manifest. | Infrastructure Lead: vulnerability triage and assigned tickets. |
| Monthly, agreed off-hours window | Apply tested routine updates; review policy/tool inventory, access roster, storage growth, and monitoring thresholds. | Service Manager: approved change and rollback evidence. |
| Quarterly | Sample security evidence, review access rights and open risks, perform an isolated restore exercise, and deliver operator refresher training. | Security Officer: audit findings; Backup Engineer: restore report. |
| Annually and after material change | Reassess risks, client obligations, recovery targets, staffing, and this plan; run a security incident tabletop. | Owner: documented review and funded action list. |
| New tool, policy, model, transport, or security fix | Run affected regression checks plus the complete deterministic suite before acceptance. Repeat live-model evaluation when model behavior or its interface changes. | Maintainer: reproducible commands and results. |

**Patch prioritization targets:** triage an actively exploited or containment-critical issue within
one operating day; suspend affected automation immediately if containment is uncertain. Target
mitigation or a tested patch within 24 hours for critical exposure, seven calendar days for high
risk, 30 for medium, and 90 for low risk. These clocks start at identification. If a safe patch is
unavailable, the Security Officer records the compensating measure, accountable owner, expiry,
and next review date. An expired exception returns to escalation; it does not silently renew.

### Controlled change and rollback

1. Open a change ticket with the affected component, current and proposed versions, advisory or
   defect, policy differences, impact, test plan, maintenance window, and rollback trigger.
   Include the Git revision, `uv.lock`, installed package versions, OS/runtime, and model identifier
   where used. `pyproject.toml` contains version ranges; do not describe those as exact pins.
2. Reproduce the current release in an isolated environment with synthetic data. Preserve its
   code, policy, dependency manifest, and verified audit evidence. Keep credentials outside Git
   and use the Provider's protected credential process.
3. Apply the candidate change in that environment. Review changes to allow rules, destinations,
   and gates explicitly. A patch must not weaken a denial or remove an attack scenario to pass.
4. Run the validation commands below. Record existing baseline failures separately; do not
   accept an unexplained security regression. Another reviewer checks security-sensitive changes.
5. Have the Service Manager schedule the change. Stop new agent tasks, resolve or cancel pending
   work without bulk approval, then stop the owning processes. Verify and copy the closed log;
   do not copy a partially written final line as a completed backup.
6. Apply the tested release and run synthetic smoke checks with a fresh audit path. Confirm an
   unknown tool is denied, the modeled chain is blocked, and an unapproved gate cannot execute.
7. If a check fails, keep automation paused. Restore the reviewed code/configuration version in
   a clean environment and repeat validation. Preserve the failed release's log separately;
   never overwrite it with the older backup. Rolling back a vulnerable version requires an
   explicit risk decision or continued suspension of the affected workflow.
8. Record the accepted revision, checks, remaining risks, and restart decision. Because live
   sequence history is not restored today, do not automatically resume a partially completed
   workflow after either upgrade or rollback.

### Validation commands

From the repository root in the configured development environment:

```powershell
python -m pytest -q
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy src

# Choose a new, unused output directory for every evaluation.
python -m src.eval.run --suite all --out results/maintenance-YYYYMMDD-run01

# Separate-process smoke test; all tools remain mocks.
python -m src.launcher --task "remediate ticket 4821" --model stub --transport loopback --audit results/maintenance-YYYYMMDD-loopback.jsonl
python -m src.audit.chain results/maintenance-YYYYMMDD-loopback.jsonl
```

The launcher smoke test should allow the first three chain steps and deny the export with
`seq.recon_register_exfil.terminal`. Verify each evaluation audit file too. Compare the suite's
false-approval, false-block, utility, **attack-attempt**, and monitor-containment measures against
the [recorded baseline](evaluation-results.md); zero attempted attacks cannot demonstrate monitor
containment. A live-model run is an additional behavioral check, not a replacement for deterministic
regressions. See the [user manual](user-manual.md) for command options.

## 4. Monitoring and performance

### Manual checks for the current prototype

During active work, an operator inspects the console's decisions, pending queue, and sequence
view. Use the full audit file for review: the web audit view is limited to recent events. Review
the process output and disk capacity, verify each closed audit log with `src.audit.chain`, and
record failures in the helpdesk queue. A successful console login proves only console availability;
the seeded demo does not prove that the launcher's monitor is healthy or connected.

Timeouts are enforced by the service's waiting gate path, not by a background queue scheduler.
`MonitorService` defaults to 300 seconds, while the demo composition defaults to two seconds.
The console's seeded item has no waiter and does not automatically time out. Establish and test
the actual deployed timeout before setting approval alerts.

### Proposed Prometheus/Grafana integration

Prometheus collects numeric time series; Grafana can query a Prometheus data source to display
them. The proposed flow is a trusted monitor/exporter and host collector → Prometheus → Grafana,
with alert routing through Alertmanager to the Provider's staffed support process.
See the official [Prometheus overview](https://prometheus.io/docs/introduction/overview/) and
[Grafana Prometheus data source documentation](https://grafana.com/docs/grafana/latest/datasources/prometheus/).

This is an integration specification, **not an installed service or an existing `/metrics`
endpoint**. Keep collection on the management side of the monitor. Restrict access to metrics,
dashboards, and alerts, and authenticate/encrypt connections that cross a trust boundary.
Monitoring must not grant an agent access to tools, policy mutation, or the approval queue.

| Proposed signal | Source / implementation needed | Initial alert and action |
|---|---|---|
| Monitor availability and collection freshness | Process/host collector plus separate exporter health; a scrape alone does not validate enforcement. | Two missed 30-second scrapes during scheduled operation: Tier 2 checks both collector and monitor. Mark missing data as unknown, not healthy. |
| Decision counts by verdict and bounded rule ID | Instrument evaluated decisions or tail verified events with durable offsets and restart deduplication. | Any modeled terminal denial: Tier 2 reviews the synthetic task or incident context. More than 20% default-denied calls in 15 minutes with at least 20 decisions: investigate policy drift. |
| Audit write errors and chain verification | Instrument write failures outside the failed audit sink; scheduled verification of consistent snapshots. | Any failure: stop new automation, preserve evidence, escalate to the Security Officer. Current JSONL alone cannot expose all its own write failures. |
| Pending approval count, oldest age, timeout count | Instrument the live service queue and resolution path. | Oldest age above 80% of the configured timeout: notify the assigned operator. More than 10 pending for five minutes: Service Manager checks capacity. Never auto-approve to clear backlog. |
| Policy/sequence evaluation latency | New histogram around evaluation, excluding operator wait and model generation. | p95 above twice the accepted staging baseline for 15 minutes and at least 100 observations: Infrastructure Lead investigates. Record the baseline with hardware and workload. |
| Disk capacity, log growth, process memory | Host collector; measure on the actual audit volume. | Disk above 80% for 15 minutes: capacity ticket; above 90% or projected exhaustion within 24 hours: suspend intake until evidence storage is safe. Review sustained memory growth. |
| Sequence eviction/expiry rates | Future live retention wiring and event emission; event types alone are not a working signal. | Enable alerts only after testing actual emission, expiry, and reconstruction. Until then, display this signal as unavailable. |

These thresholds are starting values for synthetic staging. Collect two weeks of representative
measurements and have the Service Manager approve revisions. Test each alert, recovery signal,
and route with synthetic failures before treating the dashboard as an operational control.

Use bounded labels such as tool, verdict, gate class, and release-controlled rule ID. Keep arguments,
prompts, patient data, secrets, usernames, principals, destinations, and per-call/session IDs out of
metrics labels and alert text. Hashing arguments does not establish that every other audit field
is safe to disclose. Retain detailed evidence only in access-controlled storage.

## 5. Evidence, backups, and security audits

**Prototype preservation:** after a completed run, verify the log, copy it to restricted backup
storage, and record file size, SHA-256, record count, run time, and release/policy revision in a
manifest kept separately. One owning process writes each audit file. A valid local chain cannot
prove that an attacker has not replaced the whole file or removed its tail; independent evidence
is necessary for that comparison.

**Proposed pilot targets:** back up configuration after every accepted change and closed evidence
at least daily; use a four-hour recovery-time objective for the service and a 24-hour recovery-point
objective for archived evidence. Those are planning assumptions, not measured guarantees. Daily
backup alone permits up to a day's evidence loss; independent forwarding/head sealing must be
implemented if that loss is unacceptable. The Security Officer and client owner must agree on
targets before a real pilot. Quarterly, restore to an isolated host, compare the manifest, verify
the chain, read events, and rerun synthetic checks. Record actual recovery time and any lost data.

**Retention:** preserve capstone evidence through assessment and any academic retention period.
For an operational deployment, the Security Officer must approve separate schedules for runtime
logs, backups, and compliance documentation. HIPAA-required documentation is retained for six
years from creation or last effective date, whichever is later; this is not automatically a
six-year requirement for every runtime log. Preserve relevant evidence under an incident/legal
hold. [45 CFR §164.316(b)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.316)

Do not truncate a live JSONL file or rotate it with an ordinary overwrite job. Automatic rotation
and replay across segments are future work. Stop intake and preserve the complete file before
changing paths; currently, any restart loses live sequence progress regardless of saved logs.

**Quarterly audit sample:** the Security Officer or a reviewer independent of the change author
checks at least one allow, deny, gated denial/timeout, approved synthetic operation, patch ticket,
restore result, and operator training record. Check rule traceability, actor attribution gaps,
evidence access, version correspondence, and agreement status. Include all known integrity failures
and suspected bypasses. Record each finding's severity, owner, due date, corrective action, and
retest result. Reassess after new tools, client access, incidents, or material policy changes.

## 6. Helpdesk and escalation

Use the Provider's existing ticketing process. A ticket includes UTC time, environment/release,
synthetic run or restricted evidence reference, tool and rule ID, expected and actual behavior,
impact, reproducible steps, and assigned owner. Never paste PHI, credentials, raw prompts, or
unreviewed logs into a general helpdesk ticket. The [FAQ](faq.md) is the first troubleshooting
reference; the ticket becomes the record of work and resolution.

| Priority | Example | Proposed acknowledgment and escalation |
|---|---|---|
| P1 — security or containment failure | Suspected unauthorized execution/disclosure, corrupt evidence, compromised operator account. | Immediately stop new agent tasks; acknowledge within 15 minutes during staffed operation and contact the Security Officer and Infrastructure Lead. Preserve evidence and use the Provider's incident process. |
| P2 — service unavailable or degraded | Monitor unavailable, repeated system errors, blocked legitimate work, unavailable approval path. | Acknowledge within one hour during staffed operation; Tier 2 investigates and the Service Manager assigns a recovery owner. |
| P3 — ordinary defect or improvement | Documentation confusion, noncritical dashboard issue, enhancement request. | Acknowledge within one business day; triage at the weekly review. |

These are acknowledgment targets, not promises of resolution. The prototype has no 24/7 on-call
service. Unattended operational use requires an agreed escalation rota first; otherwise pause
automation outside coverage. Never troubleshoot by disabling the monitor, erasing history, or
turning every gate into an allow. Required business work during an outage goes through the
Provider's separately authorized manual process. The Security Officer determines incident scope
and any client/regulatory notification duties; a DENY event alone does not establish a breach.

## 7. Refresher training and feedback loop

Before approval access, operators complete the [onboarding exercises](training.md) using synthetic
data. Quarterly, and after a gate/policy change or incident, repeat a short practical refresher:
read a rule-based denial, recognize the canonical chain, distinguish a demo queue from a live
waiting service, deny an unsupported request, and open a sanitized escalation ticket. Verify an
unapproved live service call times out; merely leaving the seeded console item open does not test
that behavior. Record the attendee, exercise, reviewer, result, and any required retraining.

The Service Manager reviews support and audit findings weekly. For each recurring problem:

1. Classify it as a defect, policy gap, training need, capacity issue, or accepted limitation.
2. Reproduce it with synthetic inputs and assign an owner and acceptance criteria.
3. Add a meaningful regression scenario for behavioral fixes, preserving existing attack coverage.
4. Review and release through §3; update the manual, training material, and compliance evidence.
5. Check the outcome at the next monthly review and close only with evidence of the fix.

Track overdue critical patches, integrity failures, support response time, repeat incidents,
approval timeout rate, restore success, and training completion. Evaluate false approval/block
and utility using labeled scenarios; ordinary DENY volume is not a measured false-block rate.
Quarterly management review decides priorities and risk acceptance. The proposed monitoring,
durable sequence reconstruction, approval attribution, console integration, and independent audit
preservation remain explicit backlog items until implementation and tests demonstrate completion.
