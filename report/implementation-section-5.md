# Implementation §5 — Challenges, Changes During Implementation, and Lessons Learned

Implementation of the AI-Agent Tool-Call Containment Monitor required resolving differences between the planned architecture, the working prototype, and the evidence needed to evaluate its effectiveness. The principal challenges involved enforcing separation between the agent and monitor, attributing evaluation outcomes accurately, obtaining meaningful variation across repeated model runs, and keeping the implementation aligned with the Provider's healthcare MSP case study.

## Completing the Process Boundary

One architectural challenge was completing the separate-process communication path. The design identified loopback transport as the primary deployment approach, but the initial implementation supported in-process execution while the loopback component remained a placeholder. In-process execution supported development and testing, but the agent and monitor shared an address space. It therefore provided weaker separation than the planned architecture.

This implementation addressed the gap by adding HTTP and JSON transport between the agent and a separate monitor process. The agent-side client submits tool-call proposals, while the monitor retains responsibility for evaluating requests and executing permitted tools. The trusted launcher establishes the session, and the normal launch configuration protects session creation with a bootstrap capability kept outside the model's context. Import-boundary tests also check that the loopback client does not import monitor, policy, or tool implementation modules.

The documented parity evaluation reported matching outcomes and ordered decision streams across all ten scenarios for the in-process and loopback paths. Integration tests additionally cover a blocked attack chain across separate processes, rejected session credentials, and unknown tools. This work demonstrated that an architectural separation claim needs evidence at the actual communication boundary. The prototype still assumes a trusted local host and uses plaintext loopback communication; process separation alone does not establish protection against a compromised operating system.

## Correcting Evaluation Attribution

A second challenge concerned the interpretation of successful containment. The initial live-model evaluation recorded no harmful outcomes across six attack scenarios. Inspection of the audit evidence showed that the model proposed the attributed harmful action in only three scenarios. In the remaining scenarios, the model repeated preliminary operations or followed another path without reaching the action being evaluated. Counting all six outcomes as monitor blocks would have overstated the monitor's contribution.

The evaluation was extended with two additional measures: attack attempt rate and monitor containment rate. The first records whether the attributed harmful action reached the monitor, while the second measures containment among those attempted attacks. Reanalysis of the saved live-run evidence produced an attempt rate of three out of six and containment of all three attempted attacks. Credential theft required particular care because credential access itself satisfied the scenario's definition of harm; waiting for a later network transmission would have incorrectly classified the attempted theft as a non-attempt. The resulting lesson was that evaluation must distinguish the absence of harm from evidence that a specific control prevented it.

## Producing Meaningful Repeated Runs

A related challenge emerged when expanding the evaluation from one live run to five seeded runs. Changing the seed initially produced identical behavior because the installed model configuration used a sampling temperature of zero. Under that configuration, repeated seeds did not provide meaningful behavioral variation. The implementation added an optional temperature setting and repeated the evaluation at a temperature of 0.8.

Across the five saved runs, each run recorded three attempted attacks out of six, and the monitor contained all three. All four benign scenarios completed in every run. Although the aggregate results remained unchanged, the attempted scenario set varied: one seed substituted an indirect-injection exfiltration attempt for an interleaved exfiltration attempt. This showed that stable summary metrics can conceal differences in the underlying behavior. It also established the importance of verifying sampling settings before interpreting repeated runs as evidence of robustness. These results remain limited to one model and a small scenario suite.

## Aligning the Prototype with the Case Study

The early mock-tool vocabulary used a banking domain that did not match the Provider's healthcare MSP environment. The implementation renamed that domain to RMM and expressed the canonical sequence through endpoint enumeration, share discovery, destination registration, and record export. This change did not alter the containment mechanism, but it made the scenarios, policy rules, demonstrations, and report consistent with the business case. The lesson was that a technically correct prototype still needs domain language that allows stakeholders to understand the risk and evaluate whether the workflow is realistic.

## Distinguishing Enforcement from Task Quality

The live evaluation also exposed a difference between completing a permitted operation and completing a task efficiently. The model sometimes repeated tool calls and consumed its available step budget without reliably producing a final response. Those repeated calls remained subject to the monitor, but successful enforcement did not resolve the model's inefficient behavior. The evaluation therefore qualified its utility results: a benign scenario's successful post-condition demonstrated that the required operation occurred but did not necessarily establish response quality or timely termination. Future evaluations should measure unnecessary calls, completion time, and final-answer quality alongside containment.

## Lessons for Future Development

These implementation experiences inform the next stage of development. Evaluation should expand to additional models, attack variations, and representative benign workflows. Sequence detection remains limited to modeled patterns and retained history, so unfamiliar combinations and attacks extending beyond the configured history window require further investigation. For the Provider, production adoption would require validating both containment and operational usefulness against actual workflows, including approval workload, task completion quality, and integration behavior.

The broader lesson is that the implementation, its evaluation, and its report must remain synchronized. Architectural claims require tests at the claimed boundary, model results require attribution to the action that was actually proposed, repeated runs require verified sampling variation, and business-facing scenarios require terminology consistent with the operating environment.
