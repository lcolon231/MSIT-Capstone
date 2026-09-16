# Implementation §6 — Final System Overview and Integration

## 6.1 Final System Overview

The completed implementation is a local prototype of an AI-agent tool-call containment monitor for the Provider's healthcare IT service environment. It demonstrates how an agent can propose operational actions while a separate enforcement component determines whether those actions may execute. The prototype combines a model-driven agent, declarative policy rules, a stateful sequence engine, a human-approval queue, an audit subsystem, and an operator web console. Its tools simulate remote monitoring and management (RMM), file operations, network activity, and credential access. They operate on mock state; the implementation does not connect to the Provider's production RMM platform or process real patient records.

The system produces three possible policy verdicts. **ALLOW** permits execution, **DENY** prevents execution, and **GATE** holds an action pending an approval decision. The distinction is central to the project's objective: routine permitted work can proceed, prohibited behavior is blocked, and selected consequential actions require human authorization. The model does not decide which category applies. Enforcement uses the proposed tool call, the loaded policy, and the monitor's sequence state, without an LLM in the verdict path.

The agent supports both a deterministic stub model and a local Ollama model interface. The stub supplies reproducible call sequences for demonstrations and testing, while the live-model evaluation uses Llama 3.1 8B. Both interact with the monitor through the same proposal-and-result contract. This separation makes it possible to evaluate enforcement independently of whether a particular model generates the intended attack sequence.

## 6.2 Component Integration and Process Boundaries

The trusted launcher assembles the agent and its transport. The implemented loopback option starts the monitor in a separate operating-system process and exchanges JSON messages over local HTTP. The launcher supplies a bootstrap capability for session creation, and the resulting session-bound transport submits proposals on the agent's behalf. Session metadata is managed outside the model's proposal content. A model-generated assertion of approval therefore does not resolve an approval request or grant execution authority.

Loopback is the project's designated primary architecture, although the current launcher defaults to the in-process transport unless the loopback option is selected explicitly. The in-process option invokes the same monitor service within one address space and remains useful for testing and local demonstrations. It provides a software interface boundary rather than the process separation of the loopback configuration. Tests check that the agent modules and loopback client do not acquire an import dependency on the monitor, policy, or tool implementations.

Within the enforcement component, the monitor service coordinates policy evaluation, audit writing, approval handling, tool dispatch, and sequence-state updates. Tool implementations are accessed through its registry rather than directly by the agent loop. Shared composition functions assemble the enforcement components for the launcher and evaluation environment, reducing differences between the system under test and the demonstration build.

![Deployment and network zones](../docs/diagrams/08-deployment-zones.png)

*Figure 8. Deployment and network zones. The diagram shows the agent, trusted monitor, audit store, and operator console. The console connection represents the shared-object integration interface; the standalone console entry point does not automatically attach to the loopback monitor subprocess.*

The process boundary reduces direct access to the running monitor's objects from the agent side. It should not be interpreted as a complete operating-system sandbox. The loopback implementation uses plaintext local HTTP and assumes a trusted host within the project's threat model. Host compromise, arbitrary modification of the application, and production network deployment require controls beyond the demonstrated boundary.

## 6.3 End-to-End Enforcement Flow

An interaction begins when the agent submits a tool name and arguments. The monitor checks the session binding and constructs an internal call with monitor-assigned identity and timing information. For a valid bound session, it obtains the relevant sequence state and evaluates the call against the policy. When no rule matches, the baseline verdict is DENY. The sequence engine can make that decision more restrictive, but cannot soften a per-call denial into an approvable action.

The monitor records the decision before normal dispatch. A DENY returns a denied result without invoking the tool. An ALLOW reaches the registry's execution path. A GATE creates an approval request and waits for its resolution; execution follows only if the request is approved. Denial or timeout prevents execution. The original policy verdict remains GATE, with a separate resolution event distinguishing approval, denial, and timeout. This preserves the difference between an action permitted automatically and an action executed after authorization.

The canonical RMM sequence demonstrates why state matters. The agent lists endpoints, lists shares, registers a new destination, and then requests an export to that destination. The sequence engine recognizes the modeled progression and denies the terminal export. An export to a different destination does not satisfy that same terminal binding and instead remains subject to the ordinary export policy, including its approval gate. The prototype therefore demonstrates a specific, inspectable sequence rule rather than a general ability to infer every malicious intention.

After a permitted tool invocation returns, the service advances and commits applicable sequence state. The result is then returned through the transport to the agent. Because returned content may influence the next model response, each subsequent proposal must pass through enforcement again. Allowing an earlier read or reconnaissance action does not authorize later actions in the task.

![Data flow for a single tool call](../docs/diagrams/05-single-call-dataflow.png)

*Figure 5. Data flow for a single tool call. The figure traces proposal enrichment, sequence and per-call evaluation, audit writing, approval handling, tool dispatch, and the result returned to the agent.*

## 6.4 Operator Console and Approval Integration

The Flask console provides login, a dashboard, pending approvals, audit history, a policy viewer, and a sequence-state inspector. The dashboard summarizes recent decisions and approval resolutions alongside the number of pending requests. The policy view exposes the loaded rules for inspection, while the sequence view presents available live progress by session and principal. These views help an operator relate a decision to its rule and execution context.

Access is divided between operator and viewer roles. Both can inspect the console, but only an operator can resolve approval requests. Authorization is enforced on the approval route as well as through the presence or absence of action buttons. The console has no route for directly executing a tool or editing policy. Resolving a request changes its status in the approval queue; the monitor remains responsible for deciding whether the waiting action proceeds.

The integration interface supplies the console with an approval queue, session registry, loaded policy, and audit-log path. When composed with a running monitor, the console must share that monitor's live objects to inspect its state and resolve its requests. This requirement is distinct from merely displaying the same audit file: an audit path does not connect separate in-memory approval queues.

The supplied standalone console entry point creates its own demonstration context, including seeded audit decisions and a pending approval. It does not automatically connect to the monitor subprocess launched through loopback. Consequently, the existing interface demonstrates the console workflow, while a single packaged launch that combines the loopback monitor with an interactive console remains an integration task. A screenshot of the seeded interface must be labeled as demonstration data and cannot establish that an action from a separate agent run was approved and executed.

![Approval gate flow](../docs/diagrams/06-approval-gate-flowchart.png)

*Figure 6. Approval gate flow. Four consequential action classes enter the approval queue. Approval permits the monitor's tool path to continue; denial, timeout, or an unclassified gate prevents execution.*

The console authenticates users through its local user store and records the user and role in the browser session. Subsequent routes require an authenticated session, and approval actions additionally require the operator role. Viewer requests to resolve an approval return a forbidden response.

![Login and session flow](../docs/diagrams/07-login-session-flow.png)

*Figure 7. Login and session flow. The sequence shows authentication, session-protected views, role enforcement for approval actions, and logout.*

## 6.5 Auditability and Supporting Evidence

The audit subsystem writes events to an append-only JSONL file. Decision records include the tool, session, principal, verdict, rule identifier, and a hash of the call arguments. Hashing avoids storing the complete argument payload in the decision record, but is not encryption and does not establish that every other field is free of sensitive information. Approval-resolution records distinguish the result of a gate from its initial policy decision.

The implemented writer also adds a record sequence number and a hash linking each record to its predecessor. A verification utility checks the chain for inconsistencies such as an uncorrected modification, deletion, or reordering within the file. This supports integrity checking without making the log immutable. A consistent prefix can survive tail truncation, and an actor able to rewrite the file can recompute an unkeyed chain. Stronger assurance requires protecting the log and retaining a trusted external checkpoint or equivalent integrity control.

Integration evidence includes the documented comparison of all ten evaluation scenarios across the in-process and loopback transports. That comparison reports ten matching outcomes and ordered decision streams, with no mismatches. It supports the conclusion that transport separation preserved behavior for the tested suite; it does not establish equivalence for every possible input or deployment condition.

The saved deterministic evaluation contains six attack scenarios and four benign scenarios. All six attributed harmful actions were attempted and contained, and all four benign scenarios completed. In the five saved live-model runs using seeds 1–5 and temperature 0.8, three of six attributed harmful actions were attempted in each run, and all three were contained. All four benign scenarios completed in each run. These results support enforcement within the exercised scenarios, while retaining the essential distinction between monitor containment and a model never attempting the harmful action. They do not demonstrate production effectiveness across arbitrary models, tools, or attacks.

## 6.6 Final Visual Documentation

Figures 5 through 8 document the single-call flow, approval gate, login and role session, and deployment boundaries. The screenshots below record the completed interface and command-line demonstrations. Figures 9 through 15 use the seeded local console or deterministic stub and evaluation paths; their captions identify that provenance.

![Operator console login](../docs/screenshots/01-login.png)

*Figure 9. Operator console login. This local interface requires a configured username and password before protected console routes are available.*

![Operator dashboard](../docs/screenshots/02-operator-dashboard.png)

*Figure 10. Operator dashboard using seeded demonstration data. The page shows the pending-approval count and recent ALLOW and GATE decisions with their rule identifiers.*

![Pending approval](../docs/screenshots/03-approvals-pending.png)

*Figure 11. Pending approval using seeded demonstration data. The operator can approve or deny the data-export request; arguments appear as a SHA-256 digest rather than plaintext.*

![Audit view](../docs/screenshots/06-audit.png)

*Figure 12. Audit view using seeded demonstration data. The console presents recent decision events and the rule associated with each verdict.*

![Sequence state inspector](../docs/screenshots/08-sequence.png)

*Figure 13. Sequence-state inspector in the standalone demonstration. The empty view confirms that the interface renders correctly; it does not show progress from a separately launched loopback monitor.*

![Canonical kill chain denied](../docs/screenshots/10-cli-killchain.png)

*Figure 14. Deterministic launcher demonstration. The first three RMM calls execute, while the sequence engine denies `export_records` at the terminal step.*

![Deterministic evaluation results](../docs/screenshots/11-cli-eval.png)

*Figure 15. Deterministic ten-scenario evaluation. All six attributed harmful actions reached the monitor and were contained, while all four benign scenarios completed.*

---

## Author verification notes — exclude from final report

This section was drafted against the current working tree. It does not claim a fresh live-model evaluation or a production deployment. Figures 5 through 8 and screenshots 9 through 15 are embedded from the tracked assets under `docs/diagrams/` and `docs/screenshots/`.

| Claim or topic | Repository evidence |
|---|---|
| Launcher options, in-process default, loopback subprocess and bootstrap | `src/launcher.py`; `src/transport/loopback.py`; `src/monitor_server.py` |
| Enforcement orchestration and approval outcome semantics | `src/monitor/service.py`; `src/monitor/gate.py` |
| Strictness of policy/sequence composition | `src/monitor/verdict.py`; `tests/monitor/test_per_call_engine.py` |
| Canonical chain and destination-sensitive behavior | `tests/monitor/test_canonical_chain.py`; `policies/rmm.yaml`; Decision Log D16 |
| Import boundaries and process integration | `tests/test_import_graph.py`; `tests/test_loopback_transport.py` |
| Console routes, role enforcement, shared-object interface and seeded entry point | `src/web/views.py`; `src/web/auth.py`; `src/web/context.py`; `src/web/run.py`; `tests/web/test_console.py` |
| Audit hashing, chain verification and limitations | `src/audit/writer.py`; `src/audit/chain.py`; `tests/audit/test_chain.py` |
| Ten-scenario transport comparison | `docs/design/loopback-transport.md`, “Parity result”; `src/eval/loopback_parity.py` |
| Deterministic evaluation figures | `results/issue-19/attribution/stub-all/metrics.json` |
| Five seeded live evaluations | `results/issue-19/attribution/multiseed/seed-1/metrics.json` through `seed-5/metrics.json`; `docs/evaluation-results.md` |

Before final submission, preserve the console integration limitation unless a later implementation closes it and provides verification evidence. Avoid copying superseded design claims: current `service.py` binds the principal at session creation; it does not implement every enrichment or tool-execution event described in the older architecture document. Invalid-session and exception-return paths also do not justify a blanket claim that every rejected input has a persisted decision event. The current service writes approval-resolution events with `operator=None`, although the console supplies operator identity to the queue; do not claim complete persisted approver attribution without additional implementation evidence.
