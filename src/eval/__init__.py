"""Eval — red-team scenarios, deterministic scoring, and metrics (Phase 5).

Out of scope for the Phase 2 design pass except for the scenario SCHEMA, which D13 fixes now.
Eval never influences a verdict and contains no LLM in the scoring path (D6, spec.md §10):
scoring is a deterministic per-scenario post-condition checker over recorded state
(docs/design/architecture.md §3.15).
"""
