# Issue #19 Evaluation Artifacts

Captured on 2026-08-29 with Python 3.11 on Windows/PowerShell.

- `stub-all/` — deterministic ten-scenario reference run: `metrics.json`, `summary.txt`, and one
  append-only JSONL audit log per scenario.
- `live-ollama-all/` — live `llama3.1:8b` ten-scenario run with the same artifact layout.
- `coverage.json` — pytest coverage snapshot from 2026-08-29 (244 tests, 85%). The current suite is
  792 tests at 98% coverage; see `docs/evaluation-results.md`.
- `attribution/` — the same two runs re-reported with the issue #19 attempt-attribution metrics
  (attack attempt rate + monitor containment rate). `stub-all/` is reproduced directly by the CLI
  (`--out results/issue-19/attribution/stub-all/`); `live-ollama-all/` is **not a fresh model run**
  — its `metrics.json`/`summary.txt` are produced by re-judging the committed 2026-08-29 live audit
  logs (copied in under `audit/`) through the deterministic attribution checker, so the four legacy
  rates are numerically identical to the parent `live-ollama-all/` run.

Both evaluation directories were new when invoked. Do not rerun into these paths: the audit writer
appends by design. Use a new dated or suffixed directory for another measurement.

Audit arguments are stored only as SHA-256 digests. Timestamps and generated call, session, and
approval identifiers are run-specific, so the JSONL files are evidence rather than golden fixtures.

See [`docs/evaluation-results.md`](../../docs/evaluation-results.md) for commands, expected-versus-
actual results, audit interpretation, coverage, and limitations.
