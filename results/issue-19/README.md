# Issue #19 Evaluation Artifacts

Captured on 2026-08-29 with Python 3.11 on Windows/PowerShell.

- `stub-all/` — deterministic ten-scenario reference run: `metrics.json`, `summary.txt`, and one
  append-only JSONL audit log per scenario.
- `live-ollama-all/` — live `llama3.1:8b` ten-scenario run with the same artifact layout.
- `coverage.json` — machine-readable pytest coverage report for the 244-test suite.

Both evaluation directories were new when invoked. Do not rerun into these paths: the audit writer
appends by design. Use a new dated or suffixed directory for another measurement.

Audit arguments are stored only as SHA-256 digests. Timestamps and generated call, session, and
approval identifiers are run-specific, so the JSONL files are evidence rather than golden fixtures.

See [`docs/evaluation-results.md`](../../docs/evaluation-results.md) for commands, expected-versus-
actual results, audit interpretation, coverage, and limitations.
