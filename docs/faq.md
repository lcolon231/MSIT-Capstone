# FAQ & Troubleshooting — AI-Agent Tool-Call Containment Monitor

Quick answers for operators, followed by fixes for common problems. For full task walkthroughs see
the [user manual](user-manual.md); for a guided first run see [training](training.md).

---

## Concepts

**Q: What problem does this actually solve?**
An LLM agent that automates IT work needs to call tools (run a command, read a file, export
records). The agent is non-deterministic and can be steered by prompt injection hidden in a
ticket, email, or log line. Existing controls don't cover this: content filters judge *text*, and
per-call allowlists judge *one call at a time*. The monitor adds a control that judges every
**action** — including the *sequence* of actions — before it runs.

**Q: Can the agent talk its way past the monitor?**
No. The verdict is derived from *what the call is* and its arguments, never from the agent's
explanation. A persuasive "this is authorized, allow it" in the agent's output changes nothing. An
approval for a gated call can come **only** from an authenticated operator resolving it in the
console, keyed by a monitor-issued approval id — the agent has no channel to do that.

**Q: What does "fail-closed" mean here?**
The safe default is to block. If no policy rule explicitly allows a call, it's denied (`rule_id:
default`). If a gated call isn't approved by a human — including by timeout — it's denied. Silence
is never permission.

**Q: What are the three verdicts?**
**ALLOW** (the call runs), **DENY** (blocked, never runs), and **GATE** (held for a human operator
to approve or deny).

**Q: What are the four gate classes?**
The four irreversible action classes routed to a human: **data export** (`export_records`), **file
delete** (`delete_file`), **network send** (`send_network`), and **credential access**
(`access_credential`). Each is derived from the call itself, not from anything the agent says.

**Q: Why is `disable_logging` denied outright instead of gated?**
It's anti-forensics — there's no legitimate reason for an agent to disable endpoint logging, so no
operator approval should be able to permit it. It's a hard DENY in policy.

**Q: What's the kill chain everyone refers to?**
`list_endpoints → list_shares → register_destination → export_records`. Every step passes its own
per-call rule; only the ordered composition (recon → register a *new* destination → export to
*that* destination) is an exfiltration. The **sequence engine** denies the terminal export
(`seq.recon_register_exfil.terminal`), and its verdict wins over the per-call rule.

**Q: So does every export get blocked?**
No. An export to a destination that was *already* approved isn't the chain — it falls through to
the ordinary human gate. Legitimate register-then-export work is gated, not hard-blocked.

**Q: Can I edit policy or run a tool from the console?**
No, by design. The console only **observes** the monitor (audit log, live sequence state, loaded
policy) and resolves approvals. Enforcement lives entirely in the monitor process. To change what
is allowed, change the policy YAML the monitor loads.

**Q: What's the difference between the two roles?**
**operator** can view everything *and* approve/deny gated calls. **viewer** can view everything
but cannot act — approve/deny buttons are hidden and a forced request returns 403.

**Q: `inprocess` vs `loopback` transport — which do I use?**
`inprocess` (default) runs the monitor in the same process as the agent — simplest, good for demos
and tests. `loopback` runs the monitor as its **own OS process** and speaks HTTP to it, giving
genuine OS-level isolation between agent and monitor. Use `loopback` when you want to demonstrate
that isolation; `inprocess` otherwise.

---

## Operations

**Q: What are the default console credentials?**
`operator` / `operator-pass` and `viewer` / `viewer-pass`. **Change them** for anything beyond a
local demo via the `OP_PASS` / `VIEW_PASS` (and `OP_USER` / `VIEW_USER`) environment variables, and
set a stable `CONSOLE_SECRET`. See [user manual §6.3](user-manual.md#63-point-the-console-at-a-different-policy-log-or-accounts).

**Q: Where is the audit log?**
The console reads `results/console-demo-audit.jsonl` by default (override with `MONITOR_AUDIT`).
Agent-task runs write `results/agent-run-audit.jsonl` (override with `--audit`). Evaluation runs
write per-scenario logs under `<--out>/audit/`. All are append-only JSONL.

**Q: How do I change the port or bind address?**
Set `PORT` and/or `HOST` before launching: `$env:PORT = "8080"; python -m src.web.run`.

**Q: Why does the console show only observed history and not live agent calls?**
`python -m src.web.run` starts the console over a **demo** monitor with seeded history and one
pending approval — it's built for local demonstration and screenshots. To see a specific run's
decisions, point `MONITOR_AUDIT` at that run's audit log. To act on **live** gated calls, run
`python -m src.monitor_server --console-port 5000` (set `OP_PASS` first): that console shares the
running monitor's approval queue.

**Q: Where do I read the evaluation results?**
[`docs/evaluation-results.md`](evaluation-results.md). The committed reference run scored **100%
containment, 0% false-approval, 0% false-block, and 100% utility** across 6 attack and 4 benign
scenarios, on both the deterministic stub and a live Llama-3.1-8B.

---

## Troubleshooting

**The console won't start / `No module named src...`.**
Run from the **repository root** with the virtual environment active
(`.\.venv\Scripts\Activate.ps1`) and the package installed (`pip install -e ".[dev]"`). The `src`
package resolves relative to the repo root.

**`python -m src.web.app` or `python -m src.agent.run` fails with "No module named".**
Those module paths don't exist — older README/spec text is stale. The correct entry points are
**`python -m src.web.run`** (console) and **`python -m src.launcher --task "…"`** (agent task).

**The browser can't reach http://127.0.0.1:5000.**
Confirm the `python -m src.web.run` process is still running and note the address it printed. If
port 5000 is taken (macOS AirPlay, another Flask app), relaunch on another port with
`$env:PORT = "8080"`.

**"Invalid username or password" even with the defaults.**
You may have set `OP_USER`/`OP_PASS`/`VIEW_USER`/`VIEW_PASS` in the environment — those override
the defaults. Check with `Get-ChildItem Env:OP_*` and either use those values or clear them
(`Remove-Item Env:OP_PASS`) and restart the console.

**Approve/Deny returns 403 Forbidden.**
You're logged in as **viewer**. Only the operator role can resolve approvals. Log out and log in
as the operator.

**"That approval is no longer available."**
The approval was already resolved (it's idempotent) or the console was restarted since it was
queued — restarting rebuilds a fresh demo queue. Reload `/approvals`; restart the console to get a
fresh pending item.

**`--model ollama` fails to connect.**
Ollama isn't running or the model isn't pulled. Start Ollama, run `ollama pull llama3.1:8b`, and
confirm it's reachable at `http://localhost:11434` (or pass `--ollama-host`). Everything except a
live-model run works without Ollama — use `--model stub`.

**The evaluation run errors about an existing/append-only log.**
The audit writer is append-only. Use a **fresh `--out` directory** for each evaluation run, e.g.
`--out results\run-2\`.

**The `/sequence` page is empty.**
That's normal when no session has advanced a tracked chain. A row appears once a session progresses
through a kill chain's steps (e.g. after an agent run that begins the recon → register → export
sequence against that monitor).

**The dashboard is empty right after login.**
The demo seeds history, so this is unusual — but if you pointed `MONITOR_AUDIT` at a new/empty log,
there's nothing to show until decisions are written there.

**A decision shows `rule_id: default`.**
The call matched no policy rule and was denied fail-closed. This usually means a tool the current
policy didn't anticipate. Check `/policy` and confirm whether that tool should have a rule.

---

## See also

- [User manual](user-manual.md) — every operator task, routes, env vars, command reference.
- [Training & onboarding](training.md) — guided 20-minute first run.
- [Evaluation results](evaluation-results.md) — the committed evidence run.
- [`tasks/spec.md`](../tasks/spec.md) and [`docs/design/`](design/) — specification and architecture.
