# User Manual — AI-Agent Tool-Call Containment Monitor

## Purpose and Scope

This manual provides operational guidance for authorized personnel responsible for running and supervising the AI-Agent Tool-Call Containment Monitor at the Provider, a managed service provider serving healthcare practices subject to the Health Insurance Portability and Accountability Act (HIPAA).

The document first presents routine operator procedures and then describes the advanced procedures used for system demonstration, evaluation, and deployment configuration.

For information concerning the system rationale and architecture, refer to [`tasks/spec.md`](../tasks/spec.md) and [`docs/design/`](design/). For operator onboarding, refer to [`docs/training.md`](training.md). For concise explanations and troubleshooting guidance, refer to [`docs/faq.md`](faq.md).

---

## 1. System Function

The system supports a large language model (LLM) agent that automates routine information technology tasks, including ticket triage, endpoint remediation, and log review. These tasks require the agent to invoke external tools for operations such as command execution, file access, destination registration, and record export.

The containment monitor is positioned between the agent and its tools. Before a proposed tool call can execute, the monitor assigns one of three authorization verdicts:

| Verdict | Meaning |
|---|---|
| **ALLOW** | The proposed tool call is authorized and may execute. |
| **DENY** | The proposed tool call is blocked and does not execute. |
| **GATE** | The proposed tool call is held until a human operator approves or denies it. |

Three enforcement layers contribute to the authorization decision. Every verdict is recorded in an append-only audit log and includes a traceable `rule_id`.

1. **Per-call policy** — A declarative YAML rule is matched against the proposed tool call and its arguments. If no rule matches, the request is denied according to the fail-closed policy.
2. **Sequence engine** — A kill-chain state machine evaluates compositions of individually permitted calls and blocks sequences that match defined malicious behavior, including the canonical exfiltration chain described below.
3. **Approval gate** — Four classes of irreversible actions are routed to a human operator. A missing approval or an expired approval request resolves to **DENY**.

The authorization verdict is determined by the observable tool call and its arguments rather than by the agent's textual explanation. Consequently, persuasive or misleading agent-generated text cannot change a **DENY** or **GATE** decision into an **ALLOW** decision.

### 1.1 Canonical Kill Chain

Each operation in the following sequence is individually permissible under its corresponding per-call policy. However, the ordered composition represents an exfiltration pattern, and the sequence engine denies the terminal operation:

```text
list_endpoints  →  list_shares  →  register_destination(dest)  →  export_records(to=dest)
   ALLOW             ALLOW            ALLOW                          DENY (sequence terminal)
```

An export to a pre-approved destination does not satisfy this sequence condition. Such a request is evaluated by the ordinary per-call export policy and is routed to an operator for authorization rather than being denied automatically.

---

## 2. User Roles

The operator console implements two roles. Both roles can inspect system information, but only the operator role can resolve a gated tool call.

| Role | Can view dashboard, audit, policy, and sequence state | Can approve or deny a gated call |
|---|:---:|:---:|
| **operator** | ✅ | ✅ |
| **viewer** | ✅ | ❌ (controls are hidden, and a direct request returns **403**) |

The console provides observational and approval-resolution functions only. It displays the audit log, live sequence state, and loaded policy, and it allows authorized operators to resolve pending approvals.

The console does not expose a route for executing tools or modifying policy. Enforcement remains within the monitor process.

---

## 3. One-Time Setup

Execute the following commands in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
ollama pull llama3.1:8b      # only needed for live-model runs (--model ollama)
```

Ollama is required only for live-model execution. All other procedures can be completed without it.

---

## 4. Basic Operator Procedures

### 4.1 Start the Console

Execute:

```powershell
$env:OP_PASS = "choose-an-operator-password"
$env:VIEW_PASS = "choose-a-viewer-password"
python -m src.web.run          # serves http://127.0.0.1:5000
```

The console has no default passwords. It refuses to start unless `OP_PASS` is set, and the viewer account is created only when `VIEW_PASS` is set.

This command starts the console with a demonstration instance of the monitor. The demonstration environment creates an operator account and a viewer account, loads a small amount of audit history, and queues one pending approval for a 500-record `export_records` request. This seeded activity ensures that each console view contains representative data when first opened.

### 4.2 Authenticate

Open the following address in a web browser:

```text
http://127.0.0.1:5000
```

The application redirects the user to the login page. Authenticate with the accounts configured at startup:

| Role | Username | Password |
|---|---|---|
| operator | `operator` (or `OP_USER`) | the value of `OP_PASS` |
| viewer | `viewer` (or `VIEW_USER`) | the value of `VIEW_PASS` |

> **Strong, unshared passwords are required for any use beyond a local demonstration.** Refer to §6.3.

An invalid username or password returns the user to the login page with the message *"Invalid username or password"* and an HTTP 401 response. Authentication fails closed and does not disclose which credential field was incorrect.

### 4.3 Review the Dashboard (`/`)

The dashboard displays:

- the 20 most recent authorization decisions in reverse chronological order, including the tool, verdict, and `rule_id`;
- the 20 most recent approval resolutions, including the identity of the operator responsible for each decision;
- and the current number of pending approvals.

### 4.4 Resolve a Pending Approval (`/approvals`)

Resolving pending approvals is the primary operator task.

A **GATE** decision remains pending until it is resolved by a human operator or expires. For each pending request, the console displays:

- the gate class;
- the tool name;
- and an argument digest consisting of a SHA-256 hash of the arguments.

Raw argument values are not displayed. This restriction prevents the approval interface from becoming an additional disclosure point. For example, a pending export containing protected health information must not expose that information through the console.

For authenticated users assigned to the **operator** role, each pending request includes **Approve** and **Deny** controls:

- **Approve** — authorizes the proposed tool call to execute.
- **Deny** — blocks the proposed tool call.

Both actions record the identity of the operator who resolved the request. The resolution appears immediately in the dashboard activity feed and the audit log.

A user assigned to the **viewer** role can inspect the same pending requests but cannot access the approval or denial controls.

The approval mechanism follows a fail-closed rule. If no operator resolves a gated request, the request is denied either explicitly or when the approval period expires. The absence of a response is never interpreted as authorization.

The following four action classes require human approval:

| Gate class | Tool | Basis for gating |
|---|---|---|
| Data export | `export_records` | Irreversible disclosure of records subject to HIPAA protections. |
| File delete | `delete_file` | Irreversible data loss. |
| Network send | `send_network` | Irreversible outbound transmission. |
| Credential access | `access_credential` | Disclosure of secret information. |

> Some actions are never routed through the approval gate because no operator authorization should make them permissible. For example, `disable_logging`, which represents an anti-forensics action, is denied unconditionally by policy.

### 4.5 Review the Audit Feed (`/audit`)

The audit view displays the complete recent history of authorization decisions and approval resolutions in reverse chronological order. The view is reconstructed from the append-only JSON Lines (JSONL) audit log.

This log constitutes the authoritative record of mediated tool calls and includes the `rule_id` associated with every authorization decision.

### 4.6 Inspect the Loaded Policy (`/policy`)

The policy view presents the exact policy currently enforced by the monitor. The policy is displayed both as structured rules and as its raw YAML source.

This view can be used to verify which policy is active and to examine the purpose of individual rules. Policy modification is not available through the console, consistent with the separation of responsibilities described in §2.

### 4.7 Inspect Live Sequence State (`/sequence`)

The sequence view displays the progression of each tracked kill chain for every active session. The displayed information includes:

- the chain name;
- the current state-machine node;
- bound values, such as a registered destination;
- and the time of the most recent update.

The view remains empty when no active session has advanced a monitored sequence. When a partial sequence is detected, the view allows the operator to observe its progression in real time.

### 4.8 End the Session

Navigate to:

```text
/logout
```

Alternatively, select the logout control in the console. This action clears the authenticated session and returns the user to the login page.

---

## 5. Interpreting an Authorization Decision

Every authorization decision contains three fields that appear throughout the console and audit records:

- **verdict** — the resulting authorization state: `allow`, `deny`, or `gate`;
- **rule_id** — the identifier of the rule responsible for the decision, which is always present and traceable;
- **reason** — a concise, human-readable explanation of the decision.

Examples of `rule_id` values include:

- `rmm.list_endpoints.allow`;
- `rmm.export_records.gate`;
- `rmm.disable_logging.deny`;
- `seq.recon_register_exfil.terminal`, which identifies a sequence-engine decision;
- and `default`, which identifies a fail-closed denial resulting from the absence of a matching rule.

The sequence layer takes precedence over the per-call policy layer. In the canonical kill chain, the terminal `export_records` request is denied by `seq.recon_register_exfil.terminal`, even though the per-call policy for `export_records` would ordinarily route the request through the approval gate.

A `default` `rule_id` indicates that the proposed call did not match any defined policy rule and was therefore denied under the fail-closed model. This result should be examined because it may indicate a tool or behavior that the current policy does not anticipate.

---

## 6. Advanced Procedures

### 6.1 Run an Agent Task Through the Monitor

The trusted launcher connects an agent to the containment monitor, executes a task, and reports each proposed tool call with its resulting authorization verdict.

```powershell
# Deterministic scripted kill chain — runs anywhere, no external services
python -m src.launcher --task "remediate ticket 4821" --model stub

# Same task driven by a live local Llama-3.1-8B via Ollama
python -m src.launcher --task "remediate ticket 4821" --model ollama
```

The launcher supports the following options:

| Option | Default | Purpose |
|---|---|---|
| `--task` | *(required)* | Specifies the task assigned to the agent. |
| `--model` | `stub` | Selects either the deterministic demonstration chain (`stub`) or the live model (`ollama`). |
| `--transport` | `inprocess` | Selects execution in the same process (`inprocess`) or a monitor running in an independent operating-system process over HTTP (`loopback`) for process-level isolation. |
| `--policy` | `policies/rmm.yaml` | Specifies the policy enforced by the monitor. |
| `--audit` | `results/agent-run-audit.jsonl` | Specifies the audit-log destination. |
| `--max-steps` | `25` | Sets the maximum number of agent turns. |
| `--console-port` | *(off)* | With `loopback`, makes the spawned monitor also serve the operator console on this port, on the approval queue that gated calls wait on. Requires `OP_PASS`. |
| `--attach` | *(off)* | Dispatches to a monitor already running at the given URL instead of spawning one; the bootstrap capability is read from `LOOPBACK_CAPABILITY`. |
| `--approval-timeout` | `2` (`300` with `--console-port` or `--attach`) | Sets how many seconds a gated call waits for an operator before it is denied; the client waits that long plus a margin. With `--attach`, it should match the running monitor's value. |

When `--model stub` is selected, the first three operations in the canonical sequence receive **ALLOW** verdicts, while the terminal `export_records` operation receives a **DENY** verdict from the sequence engine. This execution demonstrates the principal sequence-containment result of the project.

### 6.2 Run the Evaluation Suite

Execute:

```powershell
python -m src.eval.run --suite all --out results\my-run\
```

The `--suite` option accepts `all`, `attack`, or `benign`. The `--model` option accepts `stub`, which is the default, or `ollama`.

Because the audit writer is append-only, a new `--out` directory must be used for each evaluation run.

The specified output directory contains:

- `metrics.json` — containment, false-approval, false-block, and utility rates reported overall, by domain, and by scenario;
- `summary.txt` — a human-readable table containing the same results, which is also printed to the console;
- `audit/<scenario_id>.jsonl` — the audit log for each evaluated scenario.

The committed reference evaluation and guidance for interpreting its results are available in [`docs/evaluation-results.md`](evaluation-results.md).

### 6.3 Configure the Console Policy, Audit Log, or Accounts

The `src.web.run` module reads the following environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `HOST` / `PORT` | `127.0.0.1` / `5000` | Defines the network bind address and port. |
| `MONITOR_POLICY` | `policies/rmm.yaml` | Specifies the policy displayed in `/policy`. |
| `MONITOR_AUDIT` | `results/console-demo-audit.jsonl` | Specifies the audit log read by the console. |
| `OP_USER` / `OP_PASS` | `operator` / *(required, no default)* | Defines the operator account. The console does not start without `OP_PASS`. |
| `VIEW_USER` / `VIEW_PASS` | `viewer` / *(unset)* | Defines the viewer account, which is created only when `VIEW_PASS` is set. |
| `CONSOLE_SECRET` | *(random)* | Defines the Flask session-signing secret. A stable value must be configured for deployment. |

The following PowerShell example assigns a stronger operator password, configures a persistent session-signing secret, and changes the console port:

```powershell
$env:OP_PASS = "a-strong-operator-password"
$env:CONSOLE_SECRET = "a-long-random-string"
$env:PORT = "8080"
python -m src.web.run
```

Passwords are stored only as Werkzeug hashes. Plaintext passwords are not retained.

---

## 7. Reference Information

### 7.1 Commands

| Command | Purpose |
|---|---|
| `python -m src.web.run` | Starts the operator console. |
| `python -m src.launcher --task "…" --model stub` | Runs an agent task through the containment monitor. |
| `python -m src.eval.run --suite all --out results\<dir>\` | Runs the evaluation suite. |
| `pytest -q` | Runs the test suite. |
| `ruff check src tests` · `mypy src` | Performs linting and static type checking. |

### 7.2 Console Routes

| Route | Method | Access | Purpose |
|---|---|---|---|
| `/login` | GET/POST | anyone | Authenticates a user. |
| `/logout` | GET | anyone | Clears the current session. |
| `/` | GET | logged in | Displays recent decisions, approval resolutions, and the pending-approval count. |
| `/audit` | GET | logged in | Displays the complete recent audit feed. |
| `/approvals` | GET | logged in | Displays pending approvals; approval controls are available only to operators. |
| `/approvals/<id>/<approve\|deny>` | POST | operator only | Resolves a gated request and returns HTTP 403 for a viewer. |
| `/policy` | GET | logged in | Displays the loaded policy as structured rules and raw YAML. |
| `/sequence` | GET | logged in | Displays live kill-chain state for each session. |

> **Command entry points:** The supported modules are `src.web.run` for the operator console and `src.launcher` for agent-task execution. Some earlier material in the top-level README and specification refers to `src.web.app` and `src.agent.run`; those module paths do not exist. The commands in this manual should be used.

