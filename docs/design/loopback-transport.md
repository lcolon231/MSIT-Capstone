# Loopback transport (D11 PRIMARY) — implementation & parity record

Issue #54. Resolves the mismatch between the documentation (loopback described as the primary,
OS-isolated tamper-resistance path) and the build (previously an unimplemented stub). Option A was
taken: the transport is now implemented and exercised end-to-end.

## What was built

| Piece | File | Role |
| --- | --- | --- |
| Client half | `src/transport/loopback.py` | `Transport` over stdlib `http.client` + JSON. Imports `contract` + stdlib **only** — no `monitor`. Runs in the agent process. |
| Wire codec | `src/transport/contract.py` | `proposal_to_wire` / `result_from_wire` etc. — the single JSON shape both halves share; stdlib-only, so the client stays monitor-free. |
| Server half | `src/transport/loopback_server.py` | `LoopbackServer` on stdlib `http.server`. Decodes requests, enforces the bootstrap capability on `/session`, delegates to `MonitorService.handle`. Runs in the monitor process. |
| Monitor process | `src/monitor_server.py` | `python -m src.monitor_server` — builds the monitor (RMM or eval profile) and serves loopback. Never imports `src/agent`. |
| Launcher flag | `src/launcher.py` | `--transport loopback` spawns the monitor subprocess, mints the bootstrap capability, and speaks HTTP to it. |

Composition was factored into agent-free modules (`src/composition.py`, `src/eval/environment.py`)
so the monitor subprocess can stand up the same environments without importing the agent.

## Security properties preserved over the wire

- **Complete mediation.** `/dispatch` always flows through `MonitorService.handle`; a malformed
  body or unknown/forged session becomes a DENY `ToolResult`, never an exception.
- **Session creation is launcher-only.** `/session` requires a high-entropy bootstrap capability
  (minted by the trusted launcher, passed to the monitor by environment variable, never model
  context). Without it, no session is issued, so nothing can dispatch.
- **Self-enforcing split.** `tests/test_import_graph.py` asserts the loopback **client** closure
  never reaches `monitor`/`tools`/`policy`. Re-introducing the old `from src.monitor …` import into
  the client fails the build.

## Evidence

- `tests/test_loopback_transport.py` — the full kill chain (recon → register → export) is blocked
  with the agent and monitor in **separate OS processes**; capability rejection, forged session, and
  unknown tool all fail closed; an unreachable endpoint raises a transport error rather than hanging.
- `python -m src.launcher --task "…" --transport loopback` — the canonical demo, monitor in its own
  process, terminal export DENY'd by the sequence engine (identical to in-process).

## Parity result (item 7)

`python -m src.eval.loopback_parity` re-runs the entire scenario suite with the monitor in its own
process and compares, per scenario, the judged outcome and the ordered per-call decision stream
against the in-process run.

```
scenarios: 10  matches: 10  mismatches: 0
in-process containment_rate: 1.0
loopback  containment_rate: 1.0
PARITY: MATCH - loopback reproduces in-process
```

**All 10 scenarios decide identically over loopback and in-process.** This is expected by
construction: the monitor logic is byte-identical across transports — only the wire between agent
and monitor differs — and the deterministic checkers read the audit log, which both transports write
the same way. `tests/eval/test_loopback_parity.py` pins the guarantee on a representative
attack + benign pair so a regression in the wire path fails CI.

## Residual caveat

The loopback build terminates plaintext HTTP on `127.0.0.1` and authenticates session creation with
the bootstrap capability only; it assumes a trustworthy local loopback interface (single-host threat
model, D9). See `residual-risks.md`, cross-cutting D11 note.
