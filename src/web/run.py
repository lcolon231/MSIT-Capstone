"""Launch the operator console for a local demo / screenshots (issue #14).

Wires a console over a monitor's live objects (RMM policy), seeds an operator and a viewer
account, and pre-populates one gated approval plus a little audit history so the dashboard,
approvals, and audit views have content to show.

    $env:OP_PASS = "..."; python -m src.web.run          # http://127.0.0.1:5000
    OP_PASS=… VIEW_PASS=… CONSOLE_SECRET=… python -m src.web.run

There are no default credentials: ``OP_PASS`` is required (``OP_USER`` defaults to ``operator``),
and a viewer account exists only when ``VIEW_PASS`` is set (``VIEW_USER`` defaults to
``viewer``). The console here sits on a real composed monitor (same queue, sessions, and enforced
policy); to serve the console alongside the loopback endpoint that agents actually dispatch
through, use ``python -m src.monitor_server --console-port``.
"""

from __future__ import annotations

import os
from pathlib import Path

from src.audit.writer import AuditWriter, decision_event
from src.composition import compose_monitor
from src.monitor.gate import classify_gate
from src.monitor.types import CallId, Decision, Principal, SessionId, ToolCall
from src.transport.contract import Verdict
from src.web import ConsoleContext, UserStore, create_app, users_from_env


def _demo_call(tool: str, **args: object) -> ToolCall:
    return ToolCall(
        tool=tool,
        args=args,
        session_id=SessionId("s-demo"),
        principal=Principal("client-primary"),
        call_id=CallId("demo"),
        timestamp=0.0,
    )


def build_context() -> tuple[ConsoleContext, UserStore]:
    # Credentials first, so a missing OP_PASS stops startup before any demo history is written.
    users = users_from_env(os.environ)
    policy_path = Path(os.environ.get("MONITOR_POLICY", "policies/rmm.yaml"))
    audit_path = Path(os.environ.get("MONITOR_AUDIT", "results/console-demo-audit.jsonl"))

    # A little history so the dashboard is not empty on first load. Written BEFORE the monitor
    # is composed: its own writer then resumes this file's hash chain (two live writers on one
    # log would fork the chain).
    history = AuditWriter(audit_path)
    history.append(decision_event(_demo_call("list_endpoints"), Decision(Verdict.ALLOW, "rmm.list_endpoints.allow", "matched rule")))
    export = _demo_call("export_records", to="attacker-dropbox", count=500)
    gate_class = classify_gate(export)
    history.append(decision_event(export, Decision(Verdict.GATE, "rmm.export_records.gate", "matched rule", gate_class)))

    stack = compose_monitor(policy_path, audit_path)
    if gate_class is not None:
        stack.approvals.enqueue(export, gate_class)  # one pending approval to act on

    context = ConsoleContext(
        approvals=stack.approvals,
        sessions=stack.sessions,
        policy=stack.policy,
        audit_path=audit_path,
        policy_source=policy_path.read_text(encoding="utf-8"),
    )
    return context, users


def main() -> None:
    context, users = build_context()  # exits with a message if OP_PASS is unset
    app = create_app(context, users, secret_key=os.environ.get("CONSOLE_SECRET"))
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")))


if __name__ == "__main__":
    main()
