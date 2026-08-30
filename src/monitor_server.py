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
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
from pathlib import Path
from typing import Sequence

from src.composition import build_monitor as build_rmm_monitor
from src.eval.environment import build_eval_monitor
from src.monitor.gate import ApprovalQueue
from src.monitor.service import MonitorService
from src.transport.loopback_server import LoopbackServer

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


def _build_service(args: argparse.Namespace) -> tuple[MonitorService, ApprovalQueue | None]:
    audit_path = Path(args.audit)
    if args.profile == "eval":
        policy = Path(args.policy) if args.policy else None
        service, approvals = (
            build_eval_monitor(audit_path, policy, args.approval_timeout)
            if policy
            else build_eval_monitor(audit_path, approval_timeout_s=args.approval_timeout)
        )
        return service, approvals
    policy = Path(args.policy) if args.policy else Path("policies/rmm.yaml")
    return build_rmm_monitor(policy, audit_path, args.approval_timeout), None


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
        "--ready-banner",
        action="store_true",
        help="print 'READY <base_url>' once bound, so a parent can detect startup",
    )
    args = parser.parse_args(argv)

    service, approvals = _build_service(args)
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
