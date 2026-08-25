"""Monitor — the trusted enforcement side.

Owns the verdict engine (`verdict.py`), the kill-chain automaton (`sequence.py`), the
approval gate (`gate.py`), session identity + retention (`session.py`), the core value types
(`types.py`), and the composition root that dispatches to tools (`service.py`).

No module here may import `src/agent`. The dependency points agent → transport → service,
never back (docs/design/architecture.md §3.4–§3.9).
"""
