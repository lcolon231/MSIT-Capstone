# Propagation — edits required by D10–D13 (confirmed 2026-08-23)

Decisions are approved. This is the delta: what has to change in the existing files so the
decisions actually take effect rather than living only in the log.

---

## 1. Status flips

In `Decision Log.md`, change `Status:` to **Confirmed (2026-08-23)** on **D9, D10, D11, D12,
D13**. Delete the "Still-open" bullet on scenario labelling — it is now D13. Leave the
scope-cut bullet; it points at `spec.md` §11 and is satisfied.

---

## 2. `spec.md`

**§4 Tech stack** — replace the last bullet. Currently it says tools are in-process mocks.
It should say: the monitor runs as its own process owning policy, sequence state and the tool
implementations, exposing a decision-and-dispatch endpoint on loopback; the agent process holds
a thin client and no import path to the tools. Mock tools remain in-process **to the monitor**,
with no real egress.

**§6 Project structure** — move `tools/` under the monitor's ownership in the comment, and add:

```
src/
  transport/    → dispatch interface: in-process and loopback implementations
  agent/        → agent loop + thin dispatch client. MUST NOT import src/tools or src/policy
```

**§8 Success criteria** — amend two, add one:
- **#1 Complete mediation** — strengthen the wording: the agent does not call tools at all. It
  proposes a call; the monitor executes it after a verdict.
- **#4 Stateful sequence** — add that session identity is monitor-assigned and that the agent
  cannot reset sequence state.
- **NEW #10 — Tamper resistance.** The agent process has no import path to `src/tools` or
  `src/policy`; proven by an import-graph test.

**§9 / requirements** — two changes to carry into the report's requirements table:
- **SR-08** — keep 50 ms p95 but report the **measured** figure including loopback overhead
  (expect 1–3 ms), not the assumed one.
- **NEW SR-10** — Session identity shall be assigned by the monitor. No agent-supplied value
  shall establish, rotate or clear sequence state.

**§10 Boundaries** — add to **Never:** *let the agent supply, choose or reset a session
identifier, or clear sequence state by any means.*

**§11 Scope cuts** — insert a new item **0**, above the current item 1: degrade the monitor to
in-process, **with the threat-model caveat documented** (AL-2 drops from a property to an
assumption). This is cut before anything else, because everything below it costs rubric points
and this costs only a disclosure.

**§12 Open items** — close three: topic approval (approved 2026-08-23), organisation
confidentiality (already resolved), and D9 (closed as indirect injection). Remaining: Canvas
group weights, AI usage disclosure.

---

## 3. `todo.md`

**T2.1 scaffold** — add: `src/transport/` package; import-graph test asserting `src/agent`
cannot reach `src/tools` or `src/policy`. This test is the evidence for the new criterion #10,
so write it in Phase 2, not later.

**T3.1 sequence state machine** — replace the bullet on session state with the D12 answer:
- Composite key: monitor-assigned session id + resource principal
- Monitor assigns session identity; agent-supplied values rejected
- Idle expiry (default 30 min), logged when it fires
- Cross-session reconstruction by audit-log replay over a 24-hour lookback
- Per-subject chain cap; least-advanced-first eviction; **eviction written to the audit log**
- Tests: session-reset abuse, cross-session smear, eviction pressure

**T2.6 audit log** — add: chain-progress and eviction events are first-class log records, since
the log is now also the state store. Replay must reconstruct sequence state, not just decisions.

**T5.1 scenario format** — add the D13 labelling fields: required `atlas` technique, optional
`safetybench_mode` on STAC-adapted scenarios.

**Close** the Phase-1 carry-over item asking whether the instructor approved the topic.

---

## 4. `research.md`

In *Open questions to resolve before the build*, tick: threat model (D9), concurrent guardrails
(D10 — closed as scoped, not read), scenario labelling (D13). The STAC-repo check stays open;
it is a task for T5.2, not a decision.

---

## 5. The agent design prompt is now partly stale

The prompt I gave you tells the agent to **surface D11 and D12 rather than resolve them**. Both
are now decided, so replace that section with:

> **D11 is confirmed: separate process.** The monitor owns policy, sequence state and the tool
> implementations, and exposes a decision-and-dispatch endpoint on loopback. The agent proposes
> calls and never invokes a tool. Design `src/transport/` with two implementations behind one
> interface — in-process and loopback — so the in-process form remains available as a documented
> scope cut. Under both, `src/agent` must have no import path to `src/tools` or `src/policy`,
> and there must be a test proving it.
>
> **D12 is confirmed.** Sequence state is keyed on monitor-assigned session id plus resource
> principal. The agent cannot supply, rotate or clear a session id, and nothing the agent does
> resets state. Idle expiry defaults to 30 minutes. Cross-session progress is reconstructed by
> replaying the audit log over a 24-hour lookback — no second datastore. Per-subject chain caps
> evict least-advanced-first, and evictions are logged as their own audit events.
>
> Design to these. If any part is unimplementable as stated, stop and say so rather than
> substituting your own retention policy.

Keep `docs/design/open-questions.md` in the deliverables, but repoint it: it should now record
the **residual risks** the decisions leave behind — chains paced slower than the 24-hour window,
novel orderings the automaton has not been taught, and eviction pressure from an attacker
controlling many subjects.

---

## 6. Check-in addendum

Append to the 2026-08-23 entry in `capstone/Capstone Check-ins.md`:

> **Decisions closed the same day:** D9 (indirect injection), D10 (novelty claim scoped and
> closed without further reading), D11 (separate process), D12 (state retention), D13 (ATLAS
> labelling). No decision remains open. Phase 2 and Phase 3 are unblocked; the remaining
> outstanding items are tasks, not decisions — Canvas group weights, the ROI calculation, and
> the AI usage disclosure.
