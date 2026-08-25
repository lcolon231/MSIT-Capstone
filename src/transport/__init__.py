"""Transport layer (D11) — the boundary between the untrusted agent and the monitor.

Two implementations behind one `Transport` interface (`client.py`):
  - `loopback.py`  — separate process over stdlib HTTP/JSON on loopback (D11 PRIMARY).
  - `inprocess.py` — same address space, direct call (documented scope cut).

`contract.py` holds the only DTOs the agent is allowed to see. The agent imports
`contract` and `client` and NOTHING else from `src/` (see tests/test_import_graph.py).
"""
