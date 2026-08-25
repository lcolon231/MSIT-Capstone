"""Audit — append-only JSONL log + replay (criterion #8, D12).

The log is both the tamper-evident record of every decision AND the single source of truth
from which sequence state is reconstructed (D12.4 — no second datastore). Arguments are hashed,
never logged in plaintext. The audit log makes no decisions; it is a sink and a source
(docs/design/architecture.md §3.11).
"""
