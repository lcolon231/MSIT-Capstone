# User Manual — AI-Agent Tool-Call Containment Monitor

This manual is for the **operators** who run and supervise the containment monitor at the
Provider (a managed service provider serving HIPAA-covered healthcare practices). It covers the
day-to-day operator tasks first, then the advanced tasks used for demonstrations, evaluation, and
deployment tuning.

For *why* the system is built this way, see [`tasks/spec.md`](../tasks/spec.md) and
[`docs/design/`](design/). For onboarding, start with [`docs/training.md`](training.md). For quick
answers and fixes, see [`docs/faq.md`](faq.md).

---

## 1. What the monitor does

An LLM agent automates routine IT work (ticket triage, endpoint remediation, log review). To do
that work it calls **tools** — run a command, read a file, register a destination, export records.
The monitor sits **between the agent and its tools** and gives every proposed call one of three
verdicts *before* it can execute:

| Verdict | Meaning |
|---|---|
| **ALLOW** | The call runs. |
| **DENY** | The call is blocked and never runs. |
| **GATE** | The call is held for a human operator to approve or deny. |

Three enforcement layers produce the verdict, and every verdict is written to an append-only audit
log with a traceable `rule_id`:

1. **Per-call policy** — a declarative YAML rule matched against the call and its arguments. **No
   matching rule means DENY** (fail-closed).
2. **Sequence engine** — a kill-chain state machine that blocks a *composition* of individually
   permitted calls (the canonical exfiltration chain below).
3. **Approval gate** — four irreversible action classes are routed to a human. No approval, or a
   timeout, resolves to **DENY**.

**The single most important property:** the verdict depends on *what the call is*, never on what
the agent *says* about it. Persuasive agent text cannot turn a DENY or a GATE into an ALLOW.

### The canonical kill chain

Each step below is individually harmless and passes its per-call rule. Only the ordered
composition is an exfiltration, and the sequence engine denies the final step:

```
list_endpoints  →  list_shares  →  register_destination(dest)  →  export_records(to=dest)
   ALLOW             ALLOW            ALLOW                          DENY (sequence terminal)
```

An export to a *pre-approved* destination is not the chain — it falls through to the ordinary
per-call export gate and is routed to an operator instead of hard-blocked.

---

## 2. Roles

The console has two roles. Both can see everything; only the operator can act on a gated call.

| Role | Can view dashboard, audit, policy, sequence | Can approve / deny a gated call |
|---|:---:|:---:|
| **operator** | ✅ | ✅ |
| **viewer** | ✅ | ❌ (buttons hidden; a forced request returns **403**) |

The console **only observes** the monitor (audit log, live sequence state, loaded policy) and
resolves approvals. It has no route that executes a tool or edits policy — enforcement stays
entirely in the monitor process.

---

## 3. Setup (once)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
ollama pull llama3.1:8b      # only needed for live-model runs (--model ollama)
```

Everything except a live-model run works without Ollama.

---

## 4. Basic operator tasks

### 4.1 Start the console

```powershell
$env:OP_PASS = "choose-an-operator-password"
$env:VIEW_PASS = "choose-a-viewer-password"
python -m src.web.run          # serves http://127.0.0.1:5000
```

There are no default passwords: the console refuses to start without `OP_PASS`, and the viewer
account exists only when `VIEW_PASS` is set.

This launches the console over a demo monitor: it seeds an operator and a viewer account,
pre-loads a little audit history, and queues **one pending approval** (a 500-record
`export_records`) so every view has something to show on first load.

### 4.2 Log in

Open http://127.0.0.1:5000. You are redirected to the login page. Sign in with:

| Role | Username | Password |
|---|---|---|
| operator | `operator` (or `OP_USER`) | the value of `OP_PASS` |
| viewer | `viewer` (or `VIEW_USER`) | the value of `VIEW_PASS` |

> Use strong, unshared passwords for anything beyond a local demo. See §6.3.

A wrong username or password returns to the login page with *"Invalid username or password"*
(HTTP 401) — the login is fail-closed and never says which field was wrong.

### 4.3 Read the dashboard (`/`)

The dashboard shows:

- the **20 most recent decisions** (newest first), each with its tool, verdict, and `rule_id`;
- the **20 most recent approval resolutions** (who approved/denied what);
- a **pending-approvals count**.

### 4.4 Handle a pending approval (`/approvals`) — the core operator task

A GATE decision waits here until a human resolves it. For each pending item the console shows the
**gate class**, the **tool**, and an **argument digest** (a SHA-256 hash of the arguments, never
the raw values — a pending PHI export must not leak PHI into the console).

As an **operator**, each row has **Approve** and **Deny** buttons:

- **Approve** — the call is permitted to run.
- **Deny** — the call is blocked.

Both actions record *who* decided and appear immediately on the dashboard's resolution feed and in
the audit log. A **viewer** sees the same list without buttons.

**Fail-closed rule to remember:** if no operator acts, the gated call is **denied** — by explicit
deny or by timeout. Silence is never an approval.

**The four gate classes** and the tools that trigger them:

| Gate class | Tool | Why it gates |
|---|---|---|
| Data export | `export_records` | Irreversible disclosure of records (HIPAA). |
| File delete | `delete_file` | Irreversible data loss. |
| Network send | `send_network` | Irreversible outbound transmission. |
| Credential access | `access_credential` | Secret disclosure. |

> Some actions are **never** gated because no approval should make them possible — e.g.
> `disable_logging` (anti-forensics) is denied outright by policy.

### 4.5 Review the audit feed (`/audit`)

The full recent decision + resolution history, newest first, reconstructed from the append-only
JSONL log. This is the record of record: every mediated call is here with its `rule_id`.

### 4.6 View the loaded policy (`/policy`)

Read-only view of the exact policy the monitor is enforcing, shown as both structured rules and
the raw YAML source. Use it to confirm which policy is live and what each rule does. You cannot
edit policy from the console — that is deliberate (see §2).

### 4.7 Inspect live sequence state (`/sequence`)

Shows, per active session, how far each tracked kill chain has progressed: the chain name, current
state-machine node, any bound values (e.g. a registered destination), and the last-updated time.
Empty when no session has advanced a chain. This is where you watch a partial chain form in real
time.

### 4.8 Log out

Click **log out** in the console header. This clears the session and returns you to the login
page. Sessions also end on their own after 30 minutes without activity or 8 hours after login.

---

## 5. Understanding a decision

Every decision carries three fields you will see throughout the console and logs:

- **verdict** — `allow` / `deny` / `gate`.
- **rule_id** — the exact rule that decided, always present and traceable. Examples:
  `rmm.list_endpoints.allow`, `rmm.export_records.gate`, `rmm.disable_logging.deny`,
  `seq.recon_register_exfil.terminal` (sequence engine), `default` (fail-closed — no rule matched).
- **reason** — a short human-readable explanation.

Precedence: the **sequence layer wins over the per-call layer**. In the kill chain, the final
`export_records` is denied by `seq.recon_register_exfil.terminal` even though the per-call rule for
`export_records` would only gate it. Seeing a `default` `rule_id` means the call matched nothing
and was denied fail-closed — worth noticing, because it usually means a tool the policy didn't
anticipate.

---

## 6. Advanced tasks

### 6.1 Run an agent task through the monitor

The trusted launcher wires an agent to the monitor and runs a task, printing each proposed call
with its verdict:

```powershell
# Deterministic scripted kill chain — runs anywhere, no external services
python -m src.launcher --task "remediate ticket 4821" --model stub

# Same task driven by a live local Llama-3.1-8B via Ollama
python -m src.launcher --task "remediate ticket 4821" --model ollama
```

Key options:

| Option | Default | Purpose |
|---|---|---|
| `--task` | *(required)* | The task handed to the agent. |
| `--model` | `stub` | `stub` = deterministic demo chain; `ollama` = live model. |
| `--transport` | `inprocess` | `inprocess` = same process; `loopback` = monitor in its **own OS process** over HTTP (genuine isolation). |
| `--policy` | `policies/rmm.yaml` | Policy the monitor enforces. |
| `--audit` | `results/agent-run-audit.jsonl` | Where the audit log is written. |
| `--max-steps` | `25` | Cap on agent turns. |
| `--console-port` | *(off)* | Loopback only: the spawned monitor also serves the operator console on this port, on the same approval queue the agent's gated calls wait on. Requires `OP_PASS`. |
| `--attach` | *(off)* | Dispatch to a monitor already running at this URL (e.g. `http://127.0.0.1:8787`) instead of spawning one; its capability comes from `LOOPBACK_CAPABILITY`. |
| `--approval-timeout` | `2` (`300` with `--console-port` or `--attach`) | Seconds a gated call waits for an operator before it is denied. The client waits that long plus a margin. With `--attach`, match the running monitor's `--approval-timeout`. |

With `--model stub` you will see the first three steps ALLOW and the terminal `export_records`
DENY'd by the sequence engine — the project's headline result.

### 6.2 Run the evaluation suite

```powershell
python -m src.eval.run --suite all --out results\my-run\
```

`--suite` accepts `all`, `attack`, or `benign`; `--model` accepts `stub` (default) or `ollama`.
Because the audit writer is append-only, **use a fresh `--out` directory for each run.** Outputs
written under `--out`:

- `metrics.json` — containment / false-approval / false-block / utility rates (overall, per
  domain, per scenario);
- `summary.txt` — the same as a readable table (also printed to the console);
- `audit/<scenario_id>.jsonl` — the audit log for each scenario.

The committed reference run and how to read it are in
[`docs/evaluation-results.md`](evaluation-results.md).

### 6.3 Point the console at a different policy, log, or accounts

`src.web.run` reads these environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `HOST` / `PORT` | `127.0.0.1` / `5000` | Bind address. |
| `MONITOR_POLICY` | `policies/rmm.yaml` | Policy shown in `/policy`. |
| `MONITOR_AUDIT` | `results/console-demo-audit.jsonl` | Audit log the console reads. |
| `OP_USER` / `OP_PASS` | `operator` / *(required, no default)* | Operator account. The console will not start without `OP_PASS`. |
| `VIEW_USER` / `VIEW_PASS` | `viewer` / *(unset)* | Viewer account; created only when `VIEW_PASS` is set. |
| `CONSOLE_SECRET` | *(random)* | Flask session-signing secret. Set a stable value in deployment. |

Example (PowerShell):

```powershell
$env:OP_PASS = "a-strong-operator-password"
$env:CONSOLE_SECRET = "a-long-random-string"
$env:PORT = "8080"
python -m src.web.run
```

Passwords are stored only as werkzeug hashes; plaintext is never retained.

---

## 7. Reference

### Commands

| Command | Purpose |
|---|---|
| `python -m src.web.run` | Start the operator console. |
| `python -m src.launcher --task "…" --model stub` | Run an agent task through the monitor. |
| `python -m src.eval.run --suite all --out results\<dir>\` | Run the evaluation suite. |
| `pytest -q` | Run the test suite. |
| `ruff check src tests` · `mypy src` | Lint and type-check. |

### Console routes

| Route | Method | Access | Purpose |
|---|---|---|---|
| `/login` | GET/POST | anyone | Log in. |
| `/logout` | GET | anyone | Clear session. |
| `/` | GET | logged in | Dashboard: recent decisions, resolutions, pending count. |
| `/audit` | GET | logged in | Full recent audit feed. |
| `/approvals` | GET | logged in | Pending approvals (operator sees buttons). |
| `/approvals/<id>/<approve\|deny>` | POST | operator only | Resolve a gated call (403 for viewer). |
| `/policy` | GET | logged in | Loaded policy (structured + raw YAML). |
| `/sequence` | GET | logged in | Live kill-chain state per session. |

> **Note on commands:** the correct entry points are `src.web.run` (console) and `src.launcher`
> (agent task). Some older text in the top-level README/spec refers to `src.web.app` and
> `src.agent.run`; those module paths do not exist. Use the commands in this manual.
