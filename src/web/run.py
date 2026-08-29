"""Launch the operator console for a local demo / screenshots (issue #14).

Wires a console over a monitor's live objects (banking policy), seeds an operator and a viewer
account, and pre-populates one gated approval plus a little audit history so the dashboard,
approvals, and audit views have content to show.

    python -m src.web.run          # http://127.0.0.1:5000
    OP_PASS=… VIEW_PASS=… CONSOLE_SECRET=… python -m src.web.run

Credentials default to operator / operator-pass and viewer / viewer-pass — override via env for
anything beyond a local demo.
"""

from __future__ import annotations

import os
from pathlib import Path

from src.audit.writer import AuditWriter, decision_event
from src.monitor.gate import ApprovalQueue, classify_gate
from src.monitor.session import RetentionConfig, SessionRegistry
from src.monitor.types import CallId, Decision, Principal, SessionId, ToolCall
from src.policy.loader import load_policy
from src.transport.contract import Verdict
from src.web import ConsoleContext, Role, UserStore, create_app


def _demo_call(tool: str, **args: object) -> ToolCall:
    return ToolCall(
        tool=tool,
        args=args,
        session_id=SessionId("s-demo"),
        principal=Principal("acct-1"),
        call_id=CallId("demo"),
        timestamp=0.0,
    )


def build_context() -> tuple[ConsoleContext, UserStore]:
    policy_path = Path(os.environ.get("MONITOR_POLICY", "policies/banking.yaml"))
    audit_path = Path(os.environ.get("MONITOR_AUDIT", "results/console-demo-audit.jsonl"))
    audit = AuditWriter(audit_path)
    sessions = SessionRegistry(audit, RetentionConfig())
    approvals = ApprovalQueue()

    # A little history so the dashboard is not empty on first load.
    audit.append(decision_event(_demo_call("get_balance"), Decision(Verdict.ALLOW, "banking.get_balance.allow", "matched rule")))
    transfer = _demo_call("transfer_funds", to="acme-1", amount=500)
    audit.append(decision_event(transfer, Decision(Verdict.GATE, "banking.transfer_funds.gate", "matched rule")))
    gate_class = classify_gate(transfer)
    if gate_class is not None:
        approvals.enqueue(transfer, gate_class)  # one pending approval to act on

    context = ConsoleContext(
        approvals=approvals,
        sessions=sessions,
        policy=load_policy(policy_path),
        audit_path=audit_path,
        policy_source=policy_path.read_text(encoding="utf-8"),
    )
    return context, _seed_users()


def _seed_users() -> UserStore:
    users = UserStore()
    users.add(os.environ.get("OP_USER", "operator"), os.environ.get("OP_PASS", "operator-pass"), Role.OPERATOR)
    users.add(os.environ.get("VIEW_USER", "viewer"), os.environ.get("VIEW_PASS", "viewer-pass"), Role.VIEWER)
    return users


def main() -> None:
    context, users = build_context()
    app = create_app(context, users, secret_key=os.environ.get("CONSOLE_SECRET"))
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")))


if __name__ == "__main__":
    main()
