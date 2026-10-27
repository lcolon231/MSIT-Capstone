# Prompt: Assignment 2 Executive Summary

Copy everything below the line into Claude (or another assistant) from inside this repository.

---

You are helping me write **Assignment 2: Executive Summary** for my MSIT IT Capstone at the
University of West Florida (instructor: Dr. Mahd Alzoubi). The executive summary is a
stand-alone companion to my full capstone report. It is written for an executive, business
stakeholder, or hiring manager who will never read the full report.

## Source material (read these first; use only facts found in them)

- `report/phase1-chapters.md`: company profile ("the Provider"), business case, problem
  statement, impact analysis, security concerns, existing technologies, proposed solution,
  requirements, estimated cost, and *Limitations of available data*.
- `README.md` and `docs/design/`: what the containment monitor is and its three enforcement
  layers (per-call policy, kill-chain sequence evaluation, human approval gate) plus the
  append-only audit log and operator console.
- `report/implementation-section-5.md`, `report/implementation-section-6.md`: what was built and
  the implementation limitations that must be preserved.
- `docs/evaluation-results.md` and `results/issue-19/`: the red-team evaluation, both the
  deterministic stub run and the live Ollama `llama3.1:8b` run.
- `report/security-compliance-sections.md`, `docs/compliance-mapping.md`: HIPAA alignment.
- `report/review-continuous-improvement.md`, `docs/maintenance-plan.md`: prototype limitations
  and next steps.

Do not invent numbers, clients, incidents, costs, or citations. If a fact I need is missing,
write `[TODO: ...]` in its place and list it at the end. Keep the organisation confidential:
call it "the Provider" and do not add identifying details.

## Required structure

Use exactly these three section headings, in this order. Weave all six required components into
them as shown.

1. **Introduction** covers *The Subject*. Name the organisation (a regional managed service
   provider serving HIPAA-covered healthcare practices), the IT/security challenge (AI agents
   with tool access can take harmful, irreversible actions, including exfiltrating PHI), and the
   goal of the solution. Lead with impact: why this matters to the business.
2. **Analysis and Findings** covers *Methods and Analysis* and *Findings*. Briefly describe the
   methods: risk and impact analysis, threat modelling, review of existing technologies,
   requirements gathering, prototyping, and red-team evaluation with six attack and four benign
   scenarios. Then state the key results at an executive level: containment, false-approval,
   false-block, and utility rates. Report the live-model results honestly: the monitor contained
   every attack that reached it, and some attacks were never attempted by the live model. Do not
   overclaim. One small table of results is allowed if it saves words.
3. **Conclusion and Recommendations** covers *Conclusion*, *Recommendations*, and *Limitations*.
   State the proposed solution and how it reduces risk. Give three to five actionable
   recommendations tied directly to the findings, such as a staged pilot, policy tuning, and
   operator training. Close with a short, candid *Limitations* paragraph covering scope, small
   scenario set, single local model, prototype integration gaps, and limited cost data, then
   next steps for the Provider.

## Rubric to satisfy (100 points)

| Criterion | Points |
|---|---:|
| Subject and Introduction | 15 |
| Methods and Analysis | 15 |
| Findings | 20 |
| Conclusion and Recommendations | 20 |
| Limitations | 10 |
| Writing Quality and Conciseness | 10 |
| Formatting and Citations | 10 |

## Writing rules

- Length: 2 to 3 double-spaced pages, excluding the title page. That is roughly 600 to 850
  words of body text. Report the final word count.
- Audience: non-technical executives. Use plain language. Define any unavoidable technical term
  in a few words the first time, for example "large language model (LLM)" or "fail-closed".
- Do not copy paragraphs from the full report. Rewrite everything for this audience.
- No step-by-step technical detail, code, commands, or file paths in the summary itself.
- Professional, confident, third-person tone. No grammatical errors.
- Cite external sources (HIPAA, breach-cost figures, prior research) in APA 7th edition, using
  the sources already listed in `report/phase1-chapters.md`. Include a References list. It does
  not count toward the page limit.

## Formatting (for the final .docx)

- Times New Roman, 12 pt body, 14 pt headings, double-spaced, headings left-justified.
- Leave a placeholder note for the official UWF title page from Canvas.
- File name: `LastName_FirstName_Executive_Summary.docx`.

## Output

1. The full executive summary in Markdown, with the three headings above.
2. A References section in APA format.
3. A checklist confirming each of the six components and three sections is present, with the
   word count.
4. A list of any `[TODO: ...]` items I must fill in.
5. Then produce the formatted Word document from that text, applying the formatting above.
