# AI-Agent Tool-Call Containment Monitor

A **fail-closed runtime containment monitor** that sits between an LLM agent and its tools. Every
tool call is intercepted and receives **ALLOW / DENY / GATE** *before* execution, judged by what the
call is — never by what the agent says about it. Built for the CIS 6950 IT Capstone as an industry
case study for a managed service provider serving HIPAA-covered healthcare practices.

Three enforcement layers, plus an append-only audit log and an operator web console:

1. **Per-call, argument-aware policy** — declarative YAML; no matching rule means DENY.
2. **Stateful sequence evaluation** — a kill-chain state machine that blocks named malicious chains
   whose individual steps all pass per-call checks.
3. **Human approval gate** — four irreversible classes route to a human via a web console.

See `tasks/spec.md` for the full specification and `docs/design/` for the architecture.

## Commands

```powershell
# Setup
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
ollama pull llama3.1:8b

# Run the console (login page + dashboard + approvals)
python -m src.web.app                      # http://localhost:5000

# Run an agent task through the monitor
python -m src.agent.run --task "remediate ticket 4821"

# Red-team evaluation
python -m src.eval.run --suite all --out results/

# Quality gates
pytest -q
pytest --cov=src --cov-report=term-missing
ruff check src tests ; ruff format --check src tests ; mypy src
```
