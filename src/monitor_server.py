"""Monitor process entrypoint for the loopback path (D11 PRIMARY).

Runs the monitor as its OWN OS process, serving the loopback endpoint. The agent process
(launcher / eval harness) talks to it only over HTTP; tool and policy objects live exclusively
here. This is the deployment that backs the OS-level isolation claim — with it, a compromised
agent has no in-memory object to reach, only a socket that answers with mediated `ToolResult`s.

    python -m src.monitor_server --profile rmm  --audit results/loopback-audit.jsonl --port 8787
    python -m src.monitor_server --profile eval --audit results/eval.jsonl --approve-gates

The bootstrap capability is read from the ``LOOPBACK_CAPABILITY`` environment variable (never an
argv, so it does not appear in the process table). When set, the client must present it to open a
session. This module may import the enforcement side and the composition builders, but NOT the
agent — it runs in the trusted monitor process.

``--console-port`` (rmm profile) also serves the operator console from THIS process, wired to the
monitor's own approval queue, session registry, and enforced policy — so an operator's approve /
deny actually releases or blocks the waiting call. The console refuses to start unless
``OP_PASS`` is set (``OP_USER`` defaults to ``operator``; ``VIEW_USER``/``VIEW_PASS`` add an
optional read-only viewer; ``CONSOLE_SECRET`` signs session cookies):

    $env:OP_PASS = "..."; python -m src.monitor_server --profile rmm --console-port 5000
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
from pathlib import Path
from typing import Mapping, Sequence

from werkzeug.serving import BaseWSGIServer, make_server

from src.composition import MonitorStack, compose_monitor
from src.eval.environment import build_eval_monitor
from src.monitor.gate import ApprovalQueue
from src.monitor.service import MonitorService
from src.transport.loopback_server import LoopbackServer
from src.web import ConsoleContext, Role, UserStore, create_app

CAPABILITY_ENV = "LOOPBACK_CAPABILITY"


def _auto_approver(approvals: ApprovalQueue, stop: threading.Event) -> threading.Thread:
    """Background operator that approves any pending gate — the loopback-side equivalent of the
    eval runner's benign approver, so a gated legitimate action can proceed under loopback."""

    def run() -> None:
        while not stop.is_set():
            for pending in approvals.list_pending():
                approvals.resolve(pending.approval_id, True, "operator")
            time.sleep(0.005)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def _build_service(
    args: argparse.Namespace,
) -> tuple[MonitorService, ApprovalQueue | None, MonitorStack | None]:
    """The service, the queue an auto-approver may attach to (eval only), and — for the rmm
    profile — the full stack the console wires into."""
    audit_path = Path(args.audit)
    if args.profile == "eval":
        policy = Path(args.policy) if args.policy else None
        service, approvals = (
            build_eval_monitor(audit_path, policy, args.approval_timeout)
            if policy
            else build_eval_monitor(audit_path, approval_timeout_s=args.approval_timeout)
        )
        return service, approvals, None
    policy = Path(args.policy) if args.policy else Path("policies/rmm.yaml")
    stack = compose_monitor(policy, audit_path, args.approval_timeout)
    return stack.service, None, stack


def console_users(env: Mapping[str, str]) -> UserStore:
    """Operator (required) and optional viewer accounts from the environment. There is no
    default operator password: a real monitor's console must not ship with a guessable one."""
    op_pass = env.get("OP_PASS")
    if not op_pass:
        raise SystemExit("--console-port requires the OP_PASS environment variable")
    users = UserStore()
    users.add(env.get("OP_USER", "operator"), op_pass, Role.OPERATOR)
    view_pass = env.get("VIEW_PASS")
    if view_pass:
        users.add(env.get("VIEW_USER", "viewer"), view_pass, Role.VIEWER)
    return users


def console_context(stack: MonitorStack) -> ConsoleContext:
    """The console's handle into THIS monitor: same queue, sessions, enforced policy, and log."""
    try:
        source = stack.policy_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        source = "# policy file unreadable — the monitor is enforcing DENY-ALL (fail-closed)"
    return ConsoleContext(
        approvals=stack.approvals,
        sessions=stack.sessions,
        policy=stack.policy,
        audit_path=stack.audit_path,
        policy_source=source,
    )


def start_console(
    stack: MonitorStack, host: str, port: int, env: Mapping[str, str]
) -> BaseWSGIServer:
    """Serve the console on a background thread of the monitor process; caller shuts it down."""
    app = create_app(console_context(stack), console_users(env), env.get("CONSOLE_SECRET"))
    server = make_server(host, port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.monitor_server",
        description="Run the containment monitor as a loopback server (its own process).",
    )
    parser.add_argument("--profile", choices=("rmm", "eval"), default="rmm")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--policy", default=None, help="policy path (profile default if omitted)")
    parser.add_argument("--audit", default="results/loopback-audit.jsonl")
    parser.add_argument("--approval-timeout", type=float, default=2.0, dest="approval_timeout")
    parser.add_argument(
        "--approve-gates",
        action="store_true",
        help="auto-approve pending gates (benign eval scenarios only)",
    )
    parser.add_argument(
        "--console-port",
        type=int,
        default=None,
        dest="console_port",
        help="also serve the operator console on this port (rmm profile; needs OP_PASS)",
    )
    parser.add_argument(
        "--ready-banner",
        action="store_true",
        help="print 'READY <base_url>' once bound, so a parent can detect startup",
    )
    args = parser.parse_args(argv)
    if args.console_port is not None and args.profile != "rmm":
        parser.error("--console-port is only available with --profile rmm")

    service, approvals, stack = _build_service(args)
    console = None
    if args.console_port is not None and stack is not None:
        console = start_console(stack, args.host, args.console_port, os.environ)
    capability = os.environ.get(CAPABILITY_ENV) or None
    server = LoopbackServer(service, host=args.host, port=args.port, capability=capability)

    stop = threading.Event()
    if args.approve_gates and approvals is not None:
        _auto_approver(approvals, stop)

    if args.ready_banner:
        print(f"READY {server.base_url}", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.shutdown()
        if console is not None:
            console.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
