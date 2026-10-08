# Training and Onboarding Guide — AI-Agent Tool-Call Containment Monitor

## Purpose

This guide provides a structured introduction to the AI-Agent Tool-Call Containment Monitor from the perspective of an authorized system operator.

The walkthrough is designed to demonstrate the primary operational controls implemented by the system, including human approval gating, role-based access control, fail-closed behavior, audit logging, and sequence-based attack detection.

A complete walkthrough requires approximately **20 minutes**.

Before beginning, complete the one-time setup described in [User Manual §3](user-manual.md#3-setup-once).

Ollama is **not required** for this walkthrough. All procedures in this document use the deterministic execution path.

---

## Part 1 — System Security Model

Before interacting with the console, the operator should understand the security model implemented by the containment monitor.

Large language model agents can perform operational tasks by invoking external tools. However, because an LLM is non-deterministic, it cannot be assumed to reliably distinguish trusted instructions from untrusted data.

Potentially malicious instructions may be introduced through several sources, including:

- support tickets,
- email messages,
- log entries,
- external documents,
- or other content processed by the agent.

If the agent interprets malicious content as an instruction, it may attempt to invoke a tool in a manner that violates organizational policy.

The containment monitor is therefore designed under the assumption that the agent may become compromised or behave unexpectedly. Rather than relying on the agent's internal reasoning, the monitor evaluates each proposed tool call before execution.

Three principles define the monitor's security model.

### 1. Tool Calls Are Evaluated Independently of Agent Explanations

The monitor evaluates the actual tool invocation and its associated arguments.

The agent's textual explanation does not influence the authorization decision.

For example, an agent-generated statement claiming that an action is authorized does not override the policy applied by the monitor.

Authorization is therefore determined by observable tool-call behavior rather than by the agent's self-reported intent.

### 2. The System Fails Closed

The monitor uses a fail-closed authorization model.

If no policy explicitly permits a tool call, the call is denied.

Similarly, if an action requires human authorization but no authorized operator approves the request, the action is not permitted to execute.

The absence of an approval is therefore treated as a denial rather than as implicit permission.

### 3. Sequences of Tool Calls Are Evaluated

Individual tool calls may appear legitimate while collectively forming a malicious workflow.

For this reason, the monitor includes a sequence-detection layer that evaluates relationships among multiple tool calls.

This allows the system to identify attack chains in which each individual operation may be allowed, but the combined sequence represents behavior such as unauthorized data exfiltration.

Each proposed tool call receives one of three verdicts:

- **ALLOW** — the request is authorized and may execute.
- **DENY** — the request is blocked.
- **GATE** — the request requires authorization from a human operator before execution.

Each verdict is recorded in an append-only audit log and includes a traceable `rule_id` identifying the policy rule responsible for the decision.

---

## Part 2 — Starting the Console and Resolving an Approval

### Step 1 — Start the Web Console

Open a PowerShell terminal and execute:

```powershell
$env:OP_PASS = "choose-an-operator-password"
$env:VIEW_PASS = "choose-a-viewer-password"
python -m src.web.run
```

The console has no default passwords and does not start until `OP_PASS` is set.

Leave the process running.

Open the following address in a web browser:

```text
http://127.0.0.1:5000
```

The demonstration environment seeds the system with existing audit activity and one pending approval request.

This allows the human approval workflow to be evaluated immediately.

---

### Step 2 — Authenticate as an Operator

Use the following credentials:

| Field | Value |
|---|---|
| Username | `operator` |
| Password | the `OP_PASS` value set in Step 1 |

After authentication, the system displays the operator dashboard.

The dashboard includes:

- recent monitor decisions,
- approval-resolution history,
- and the number of currently pending approval requests.

At the beginning of the walkthrough, the pending approval count should display:

```text
1
```

---

### Step 3 — Inspect the Pending Approval

Navigate to:

```text
/approvals
```

The pending request should contain the following information:

- **Gate class:** Data export
- **Tool:** `export_records`
- **Argument digest:** SHA-256 hash

The raw arguments associated with the export are intentionally not displayed.

This behavior prevents the approval interface from becoming an additional disclosure point for sensitive data.

For example, if an export request contains protected health information, displaying the complete argument payload within the operator console could expose the same information that the monitor is intended to protect.

Instead, the system displays a cryptographic digest of the arguments.

The export request is routed to a human operator because data export represents an irreversible disclosure operation.

The implementation defines four classes of actions that require human approval:

1. **Data export**
2. **File delete**
3. **Network send**
4. **Credential access**

These actions are treated as sufficiently sensitive to require explicit authorization before execution.

---

### Step 4 — Deny the Approval Request

Select **Deny** for the pending request.

Return to the dashboard.

The interface should now show the completed resolution together with the authenticated operator's username.

The pending approval count should change from:

```text
1
```

to:

```text
0
```

Next, navigate to:

```text
/audit
```

The approval resolution should appear in the audit log.

This process demonstrates the human authorization gate.

A gated request cannot execute unless it is explicitly approved by an authenticated operator.

The agent itself cannot resolve the approval request.

Users assigned to a read-only role also cannot approve or deny gated requests.

---

### Step 5 — Verify Role-Based Access Control

Log out using the **log out** button in the console header.

Authenticate using the viewer account:

| Field | Value |
|---|---|
| Username | `viewer` |
| Password | the `VIEW_PASS` value set in Step 1 |

Return to:

```text
/approvals
```

The viewer account can inspect approval requests, but approval and denial controls are not available.

The viewer role is intentionally read-only.

If a viewer attempts to invoke the approval or denial action directly, the server returns:

```text
403 Forbidden
```

This behavior verifies that approval resolution is restricted to authorized operators.

After completing the role-based access-control test, authenticate again using the `operator` account.

---

## Part 3 — Sequence-Based Kill-Chain Detection

The sequence-detection mechanism demonstrates an important property of the containment architecture: an attack may consist of several operations that appear legitimate when evaluated independently.

Leave the web console running and open a second PowerShell terminal.

Execute:

```powershell
python -m src.launcher --task "remediate ticket 4821" --model stub
```

The launcher produces four tool calls.

Each line reports:

- the execution status,
- the authorization verdict,
- and the corresponding `rule_id`.

Expected output is similar to the following:

```text
[1] list_endpoints()                             -> EXECUTED  [allow/rmm.list_endpoints.allow]
[2] list_shares()                                -> EXECUTED  [allow/rmm.list_shares.allow]
[3] register_destination(destination=…)          -> EXECUTED  [allow/rmm.register_destination.allow]
[4] export_records(to=…, count=5000)             -> DENIED    [deny/seq.recon_register_exfil.terminal]
```

The first three operations are individually legitimate and therefore execute successfully.

However, the combined sequence represents a potentially malicious workflow:

```text
Reconnaissance
     ↓
Register a new destination
     ↓
Export records to the newly registered destination
```

This pattern is classified as an exfiltration sequence.

The sequence engine therefore denies the terminal export operation.

The relevant `rule_id` is:

```text
deny/seq.recon_register_exfil.terminal
```

The `seq` component indicates that the decision originated from the sequence-detection layer rather than from the individual tool-call policy.

This distinction is significant.

Under ordinary conditions, an export operation may qualify for a human approval gate. In this scenario, however, the relationship among the preceding tool calls causes the workflow to match a defined malicious sequence.

As a result, the sequence rule takes precedence and the final operation is denied rather than gated.

The system also distinguishes this attack pattern from legitimate workflows.

For example, an export to a destination that was previously approved does not satisfy the same sequence condition.

In that case, the request is evaluated according to the ordinary per-call policy and may be routed to a human operator for approval instead of being denied automatically.

This behavior allows the monitor to block suspicious compositions of otherwise valid actions without unnecessarily preventing legitimate administrative workflows.

---

## Part 4 — Verification Exercises

The following exercises can be used to verify understanding of the monitor's authorization behavior.

### Exercise 1 — Interpret Policy Verdicts

Run the launcher and inspect the `rule_id` associated with each tool call.

For each operation, identify:

- the execution status,
- the resulting verdict,
- the `rule_id`,
- and the reason the corresponding rule was applied.

The purpose of this exercise is to demonstrate that each authorization decision can be traced to a specific policy rule.

---

### Exercise 2 — Verify Fail-Closed Behavior

Restart the web console:

```powershell
python -m src.web.run
```

Authenticate using the `operator` account.

Navigate to:

```text
/approvals
```

Do not approve or deny the pending request.

The expected system behavior is denial if the request is never explicitly approved.

A gated request does not become authorized through inactivity.

The authorization model therefore follows the principle:

```text
No approval = DENY
```

This behavior provides a direct demonstration of the fail-closed security model.

---

### Exercise 3 — Inspect an Explicit Deny Rule

Navigate to:

```text
/policy
```

Locate the policy rule associated with:

```text
disable_logging
```

Unlike gated operations, this action is denied outright.

The reason is that disabling system logging constitutes an anti-forensics action.

Allowing an operator or agent to disable logging could prevent subsequent activity from being recorded and would weaken the auditability of the containment system.

Accordingly, the operation is classified as an unconditional denial rather than an action that can be approved through the human authorization gate.

---

### Exercise 4 — Inspect Sequence State

Navigate to:

```text
/sequence
```

Review the current sequence state.

The sequence view represents tool-call activity that is being tracked across multiple operations.

An empty sequence state indicates that no currently tracked actions satisfy the initial stages of a monitored attack sequence.

A row appears when observed activity matches part of a defined sequence and the monitor must retain state to determine whether subsequent tool calls complete the pattern.

This state allows the system to evaluate behavioral context across multiple operations rather than treating every call as an isolated event.

---

## Part 5 — Additional Documentation

The following project resources provide additional detail about system operation, evaluation, and architecture.

### User Manual

[`docs/user-manual.md`](user-manual.md)

The user manual provides the primary operational reference for the system.

It includes:

- operator procedures,
- console routes,
- environment variables,
- and command-line instructions.

### Frequently Asked Questions

[`docs/faq.md`](faq.md)

The FAQ provides concise explanations of common system behaviors and troubleshooting procedures.

### Evaluation Results

[`docs/evaluation-results.md`](evaluation-results.md)

This document contains the committed evaluation results for the containment monitor.

The reported evaluation metrics include:

- **100% containment**
- **0% false approval**
- **0% false block**
- **100% utility across the evaluation suite**

The document also describes how these metrics should be interpreted.

### System Specification and Design

[`tasks/spec.md`](../tasks/spec.md)

and

[`docs/design/`](design/)

These resources document the system specification, architectural decisions, and implementation rationale.

---

## Operator Security Considerations

Operators should understand several indicators that may require additional investigation.

### Default Policy Decisions

A `rule_id` identified as `default` indicates that the proposed tool call did not match an explicitly defined policy rule.

Under the fail-closed authorization model, such a request is denied.

A default denial may indicate that the system encountered:

- an unrecognized tool,
- a newly introduced operation,
- or behavior that has not yet been represented in the policy.

Default denials should therefore be investigated rather than ignored.

---

### Argument Digests

The argument digest displayed for sensitive gated actions is intentionally cryptographic rather than human-readable.

Its purpose is to identify the request without exposing potentially sensitive argument values in the approval interface.

If additional contextual information is required before resolving a gated request, the operator should obtain that information from the originating system rather than attempting to recover it from the digest.

---

### Approval Decisions

When sufficient evidence is not available to safely approve a gated operation, the appropriate response is denial.

A legitimate operation that is denied can generally be investigated and attempted again after authorization has been established.

In contrast, an unauthorized disclosure that has already been approved and executed may not be reversible.

This operational principle is consistent with the system's broader fail-closed security model.
