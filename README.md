# AI-Agent Tool-Call Containment Monitor

A **fail-closed runtime containment monitor** that sits between an LLM agent and its tools. Every
tool call is intercepted and receives **ALLOW / DENY / GATE** *before* execution, judged by what the
call is — never by what the agent says about it. Built for the CIS 6950 IT Capstone (University of
West Florida, MSIT) as an industry case study for a managed service provider ("the Provider")
serving about 30 HIPAA-covered healthcare practices.

Three enforcement layers, plus a hash-chained audit log and an operator web console:

1. **Per-call, argument-aware policy** — declarative YAML; no matching rule means DENY.
2. **Stateful sequence evaluation** — a kill-chain state machine that blocks named malicious chains
   whose individual steps all pass per-call checks.
3. **Human approval gate** — four irreversible classes route to a human via a web console.

## Results at a glance

Five independent live runs of the full suite (6 attack + 4 routine scenarios each) against a local
`llama3.1:8b` at temperature 0.8, 2026-09-04:

| Measure | Result |
|---|---|
| Harmful actions that got through | **0** of 30 attack runs |
| Attempted attacks stopped | **15 of 15** — 5 automatically (DENY), 10 at the human gate (GATE) |
| Routine tasks completed | **20 of 20**, 0 wrongly blocked |
| Human approvals per routine task | **≈ 1.5** (30 prompts over 20 tasks; read-only work needed none) |
| Automated tests | **792** passing, **98%** combined coverage (re-run 2026-10-28) |

What this does **not** yet show:

- The live model fully attempted only **15 of 30** attack runs; the rest never reached the
  harmful step, so they say nothing about the monitor. Containment is therefore reported over
  attempted attacks, not as a blanket 100%.
- The multi-step chain rule fired **3 of 3** times in scripted runs but **0** times live; the live
  model never produced the full recon → register → export order.
- Approvals were simulated (a mock approver approved routine requests and ignored attack requests).
- Policies were tightened after the live runs; the scripted suite was re-run with identical results,
  the live suite has not been re-run yet.

Full method, per-scenario breakdown and limitations: [`docs/evaluation-results.md`](docs/evaluation-results.md).
Raw metrics and audit logs: [`results/issue-19/`](results/issue-19/).

## Capstone deliverables

| Deliverable | Where |
|---|---|
| Project poster (source) | [`poster/`](poster/) — `build_poster.py` builds it from [`poster-copy.md`](poster/poster-copy.md); the PDF is submitted on Canvas |
| Threat model | [`threat-model.md`](threat-model.md) |
| Design decisions and rationale | [`Decision Log.md`](Decision%20Log.md) |
| Architecture and design | [`docs/design/`](docs/design/), diagrams in [`docs/diagrams/`](docs/diagrams/) |
| Console screenshots | [`docs/screenshots/`](docs/screenshots/) |
| Specification and plans | [`tasks/spec.md`](tasks/spec.md), [`tasks/plan.md`](tasks/plan.md), [`tasks/qa-redteam-plan.md`](tasks/qa-redteam-plan.md) |

Operations documentation: [user manual](docs/user-manual_thesis_version.md),
[training](docs/training_thesis_version.md), [FAQ](docs/faq.md),
[maintenance plan](docs/maintenance-plan.md), and
[compliance mapping](docs/compliance-mapping.md).

## Repository layout

```text
src/
  agent/        untrusted side: model client + agent loop (cannot import monitor, tools or policy)
  monitor/      trusted enforcement: interception, sequence engine, per-call policy, approval gate
  policy/       YAML policy loader and argument predicates
  tools/        mock RMM, file, network and credential tools (no real egress)
  transport/    agent <-> monitor contract; in-process and loopback HTTP transports
  audit/        append-only, hash-chained JSONL audit writer
  web/          Flask operator console (login, decisions, approvals, audit)
  eval/         scenario suite, deterministic checker, evaluation runner
  launcher.py   trusted composition root: wires an agent to a monitor and runs a task
policies/       declarative rules per tool domain
tests/          pytest suite (includes the import-boundary test)
results/issue-19/  committed evaluation evidence
```

## Commands

```powershell
# Setup (Python 3.11+)
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
ollama pull llama3.1:8b          # only needed for --model ollama

# Run an agent task through the monitor: scripted kill chain, no model needed
python -m src.launcher --task "remediate ticket 4821" --model stub
#   same, with the monitor in its own OS process over loopback HTTP
python -m src.launcher --task "remediate ticket 4821" --model stub --transport loopback
#   same, driven by the live local model
python -m src.launcher --task "remediate ticket 4821" --model ollama

# Operator console (no default credentials: OP_PASS is required)
$env:OP_PASS = "choose-a-password"; python -m src.web.run    # http://127.0.0.1:5000

# Red-team evaluation (use a fresh --out folder each time; audit logs are append-only)
python -m src.eval.run --suite all --out results/stub-run/
python -m src.eval.run --suite all --model ollama --seed 1 --temperature 0.8 --out results/live-seed-1/

# Quality gates
pytest -q
pytest --cov=src --cov-report=term-missing
ruff check src tests ; mypy src
```

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
