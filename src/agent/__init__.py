"""Agent — the untrusted side (D4).

Owns the agent loop and the pluggable model client. The agent proposes tool calls over an
injected `Transport`; it never calls a tool (D11). Its ENTIRE allowed import surface from
`src/` is `transport.contract` and `transport.client` — no `tools`, no `policy`, no `monitor`.
This is the tamper-resistance boundary, proven by tests/test_import_graph.py.
"""
