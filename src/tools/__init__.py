"""Tools — mock tool implementations over in-process state.

No real egress, no real filesystem (spec.md §110-111). A tool never decides whether it may
run; it is only ever reached by `MonitorService` after a Decision. The `ToolRegistry` is owned
and invoked ONLY by the monitor; the agent has no import path here
(docs/design/architecture.md §3.12, tests/test_import_graph.py).
"""
