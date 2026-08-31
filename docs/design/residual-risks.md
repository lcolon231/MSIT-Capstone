# Residual Risks — What the Confirmed Decisions Leave Open

> **Phase 2 design, v1.2 (2026-08-24).** Design-only. Each risk below follows directly from a
> *confirmed* decision — it is the price of a deliberate choice, not an implementation defect. Each
> entry states the risk, the decision it descends from, and the **design consequence**: what the
> design already does about it, and what it does not. Naming a weakness here is cheaper than finding
> it in review (working agreement).

---

## R1 — A chain paced slower than the lookback window

**Descends from:** D12.4 (cross-session progress reconstructed by replaying the audit log over a
configurable lookback window, default 24 h) and D1 (the automaton needs the ordered prefix to reach
a blocking transition).

**Risk.** An attacker who spaces the kill chain so that `list_endpoints`/`list_shares`/`register_destination` fall
*outside* the lookback window relative to the terminal `export_records` will present a fresh session
whose replay-seeded state has already forgotten the prefix. The export is then judged only per-call
(it gates as a normal D5 data export) rather than as a completed kill chain. This is the classic
"low-and-slow" evasion of any bounded-memory sequence monitor.

**Design consequence.**
- The lookback window is a **tunable knob**, not a constant — the trade is explicit: longer windows
  catch slower chains at higher replay cost (see R4). Default 24 h is a starting point, logged in
  config, not a security guarantee.
- The `resource_principal` anchor still helps: within one window, session rotation buys the attacker
  nothing (§3 of `sequence-engine.md`). The residual gap is strictly *temporal*, not identity-based.
- **Not solved:** the design does not detect a chain whose steps never co-occur within any single
  lookback window. Documenting the window length as a stated detection horizon is the honest posture;
  claiming otherwise would overstate the automaton. A snapshotting scheme (R4) can lengthen the
  effective horizon without unbounded replay, and is the recommended future work.

---

## R2 — Novel orderings the automaton has not been taught

**Descends from:** D1 (explicit, pre-modeled kill-chain automaton, chosen over taint tracking and
probabilistic reachability).

**Risk.** A bounded automaton recognizes exactly the chains encoded in its `ChainSpec`s. Any harmful
composition that is not one of them — a different recon path, a novel tool combination, a
semantically-equivalent reordering the model didn't enumerate — passes the sequence layer untouched
and is judged only per-call. This is inherent to the mechanism, not a bug (**Schneider 2000**: an
execution monitor enforces exactly the policy it is given).

**Design consequence.**
- This is stated as a **cited limitation**, in the report and in `sequence-engine.md` §11, rather
  than hidden. It is also the honest scope boundary of the novelty claim (D7/D10): the contribution
  is *deterministic, inspectable, policy-as-data* recognition of *modeled* chains, not universal
  composition safety (that would be re-implementing CaMeL, explicitly out of scope in D1).
- The per-call layer and the D5 gate remain as a backstop: even an unmodeled chain still hits
  fail-closed per-call policy and gates its irreversible steps. The sequence engine *tightens*; it
  is never the sole line of defense.
- **Not solved:** completeness against unknown compositions. Provenance/taint tracking is the
  mechanism that would close it and is named as future work, deliberately deferred for deadline and
  scope reasons.

---

## R3 — Eviction pressure from an attacker controlling many subjects

**Descends from:** D12.5 (per-subject chain caps, evicting least-advanced-first, every eviction
logged as its own audit event).

**Risk.** Chain progress is finite in-memory state keyed on `(session, principal)`. D12 caps the
number of chain records **within one subject**; it does not cap the number of subjects. An attacker
who induces calls against many mock accounts/endpoints/clients can therefore grow subject
cardinality without ever tripping a per-subject cap. Within any one flooded subject,
least-advanced-first eviction still applies, but spreading shallow progress across subjects avoids
that mechanism. The primary residual is memory pressure, followed by replay I/O when those cold
subjects are revisited.

**Design consequence.**
- For pressure *within* a subject, eviction is **never silent**: every removed chain is its own
  `EvictionEvent`. Its history remains visible and reconstructible for audit, but replay applies
  the eviction record and does not restore that chain as active state. Least-advanced-first keeps
  chains nearest a blocking transition in the live set.
- Idle expiry eventually removes inactive subject entries and logs each expiry, but the default
  30-minute interval is not a burst-cap and does not stop short-lived high-cardinality exhaustion.
- **Not solved:** total subject cardinality. There is no global subject cap or rate limit in the
  confirmed design, and inventing one here would require a new cross-subject eviction policy not
  present in D12. A production identity plane would apply per-tenant quotas/rate limits; the mock
  capstone environment instead records this as an accepted availability risk.

---

## R4 — Audit-log replay cost as the log grows

**Descends from:** D12.4 (state reconstructed by replaying the audit log; **there is no second
datastore**).

**Risk.** Reconstructing sequence state means reading and replaying audit events over the lookback
window. As the append-only JSONL grows, cold-start reconstruction and every new-session seeding cost
grow with it — linear in events within the window, and the file itself grows without bound. Left
unaddressed this becomes both a latency problem (seeding a session blocks the first dispatch) and an
operational one (an ever-growing single file).

**Design consequence.**
- The single-datastore choice is deliberate (D12.4: simplicity, one source of truth, no consistency
  problem between a state store and the audit log). The cost is accepted for the capstone's scale
  (mock tools, bounded runs), where within-window event counts are small.
- **What rotation + snapshotting would require** (recommended future work, not built now):
  - **Rotation.** Roll the JSONL by size/time into segments; replay reads only segments overlapping
    the lookback window. Keeps any single file bounded and lets old segments be archived/compressed
    without affecting live reconstruction.
  - **Snapshotting.** Periodically write a compacted `SequenceState` snapshot (per subject, with the
    watermark event id it reflects). Reconstruction then loads the latest snapshot and replays only
    events *after* its watermark — turning replay cost from "linear in window" into "linear in events
    since last snapshot." The snapshot must be treated as a *cache*, re-derivable from the log, so it
    does not become a second source of truth and reintroduce the consistency problem D12.4 avoided.
  - Both must preserve **append-only semantics** on the primary log (criterion #8): snapshots are
    auxiliary; the JSONL remains authoritative and independently replayable. Detection of historical
    edits is now built (hash chaining, issue #56 — see R5); argument hashes alone never provided log
    tamper-evidence, which is why the chain was added.
- **Not solved now:** the design keeps a single un-rotated JSONL. This is acceptable at capstone
  scale and is flagged as the first thing to add if the system were productionized.

---

## R5 — Hash chain does not detect last-record truncation

**Descends from:** issue #56 (each audit line carries `prev_sha256` + `seq`, chaining it to the
previous line so `src/audit/chain.py::verify_chain` names the first broken link).

**Risk.** Forward hash-chaining makes any edit, deletion, or reordering of an *interior* record
intrinsically detectable — the next record's `prev_sha256` (and the `seq` counter) stops matching.
It cannot, from the file alone, detect that the **last** record (or a suffix of records) was simply
dropped: the remaining prefix is still a valid, self-consistent chain. An attacker who can write to
the log file could therefore truncate the most recent events — precisely the ones describing an
in-progress compromise — without breaking verification.

**Design consequence.**
- Interior tamper-evidence (the T8.3 claim: "a mid-file edit must be detectable") **is** met and
  test-proven (`tests/audit/test_chain.py`); the append-only write path and PII-free argument
  hashing are unchanged.
- End-truncation is an inherent limit of a self-contained chain. Closing it requires **sealing the
  head out-of-band**: periodically persisting the latest line hash (and record count) to a separate
  trust domain — an append to a WORM store, a co-signed heartbeat, or the SIEM feed (§S4, issue #58),
  which independently records the same events so a truncated tail shows up as a gap between the two.
- Not built now: the capstone ships the chain and the offline verifier; out-of-band head-sealing is
  documented as the next hardening step, consistent with the single-host threat model (D9).

**Descends from:** D11 (two transports behind one interface; in-process retained as a documented
scope cut).

**Risk.** Under the **in-process** transport, the agent and the monitor share one address space.
The import-graph test (`tests/test_import_graph.py`) proves the agent has no *source-level* path to
`tools`/`policy`, but source-level isolation is not memory isolation: a compromised in-process agent
could, in principle, reach objects it never imported (reflection, shared globals). The tamper-
resistance claim is only fully true under **loopback**, where the OS process boundary makes tools and
policy literally unimportable in the agent process.

**Design consequence.** Loopback is the **D11 primary path** for exactly this reason; in-process is
documented as a convenience/scope-cut for CI and quick demos, and the report should state the
tamper-resistance claim as holding under the loopback deployment, with in-process called out as the
weaker, explicitly-labeled fallback.

**Status (issue #54).** The loopback transport is now implemented, not a stub: the client half
(`src/transport/loopback.py`, stdlib HTTP/JSON, no `monitor` import), the monitor-side server
(`src/transport/loopback_server.py`), a monitor-process entrypoint (`src/monitor_server.py`), and a
`--transport loopback` launcher flag. `tests/test_loopback_transport.py` blocks the full kill chain
with the agent and monitor in **separate OS processes**, and `src/eval/loopback_parity.py` confirms
every suite scenario decides identically over loopback and in-process. What remains a residual risk
is unchanged: the in-process fallback shares an address space, so the strongest form of the claim
requires the loopback deployment. One caveat specific to the current loopback build: it terminates
TLS-free plaintext HTTP on `127.0.0.1` and authenticates session creation with a bootstrap
capability only — it assumes a trustworthy local loopback interface (no hostile co-tenant process
binding or sniffing localhost), which is consistent with the single-host threat model (D9).
