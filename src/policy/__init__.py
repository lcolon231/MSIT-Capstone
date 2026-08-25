"""Policy — declarative, human-authored YAML (D2).

Owns the schema types (`schema.py`), the fail-closed loader (`loader.py`), and the named
predicate registry (`predicates.py`). Policy is inert data plus vetted pure predicates; it
evaluates nothing on its own and imports no monitor logic (docs/design/architecture.md §3.10).
"""
