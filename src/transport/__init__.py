"""Transport layer (D11) — the boundary between the untrusted agent and the monitor.

Two implementations behind one `Transport` interface (`client.py`):
  - `loopback.py`  — client half: talks to the monitor over stdlib HTTP/JSON on loopback, so the
    monitor runs in its own OS process (D11 PRIMARY). Imports `contract` + stdlib only.
  - `loopback_server.py` — the monitor-side half of the loopback path (imports `MonitorService`);
    kept separate so importing the client never drags the monitor into the agent process (§3.3a).
  - `inprocess.py` — same address space, direct call (documented scope cut).

`contract.py` holds the only DTOs the agent is allowed to see. The agent imports
`contract` and `client` and NOTHING else from `src/` (see tests/test_import_graph.py).
"""
