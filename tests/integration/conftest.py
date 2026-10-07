"""Shared fixtures for the end-to-end suite.

Everything is real except the LLM: the monitor is composed by `src.composition.compose_monitor`
over a temp copy of `policies/` and writes a temp audit log. The web console is built with the
PRODUCTION wiring (`src.monitor_server.console_context` + `console_users`) — the same queue,
session registry, and enforced policy the monitor blocks on — and driven by a Flask test client.
The only test-specific piece is an approval queue that signals on enqueue, injected through
`compose_monitor(approvals=...)`.
"""

from __future__ import annotations

import shutil
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

import pytest
from flask.testing import FlaskClient

from src.agent.model import ModelResponse
from src.composition import MonitorStack, compose_monitor
from src.monitor.gate import ApprovalQueue, PendingApproval
from src.monitor.service import MonitorService
from src.monitor.types import GateClass, ToolCall
from src.monitor_server import console_context, console_users
from src.transport.contract import ToolCallProposal
from src.transport.loopback import LoopbackTransport, wait_until_ready
from src.transport.loopback_server import LoopbackServer
from src.web import create_app

REPO_ROOT = Path(__file__).resolve().parents[2]
OPERATOR = ("op", "op-pass")
VIEWER = ("viewer", "viewer-pass")
CONSOLE_ENV = {
    "OP_USER": OPERATOR[0],
    "OP_PASS": OPERATOR[1],
    "VIEW_USER": VIEWER[0],
    "VIEW_PASS": VIEWER[1],
}


class ObservableQueue(ApprovalQueue):
    """The real queue, plus an Event set on every enqueue so a test can wait for a GATE to
    reach the operator without sleeping or polling."""

    def __init__(self) -> None:
        super().__init__()
        self.enqueued = threading.Event()

    def enqueue(self, call: ToolCall, gate_class: GateClass) -> PendingApproval:
        record = super().enqueue(call, gate_class)
        self.enqueued.set()
        return record


class Wired(MonitorStack):
    """A composed MonitorStack whose queue is an ObservableQueue (typing aid only)."""

    approvals: ObservableQueue


@pytest.fixture()
def policy_dir(tmp_path: Path) -> Path:
    """A private, writable copy of the shipped policies/ directory."""
    target = tmp_path / "policies"
    shutil.copytree(REPO_ROOT / "policies", target)
    return target


@pytest.fixture()
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit" / "audit.jsonl"


@pytest.fixture()
def build_wired(policy_dir: Path, audit_path: Path) -> Callable[..., Wired]:
    """Factory: compose a monitor exactly as production does, with an observable queue."""

    def build(
        policy_path: Path | None = None,
        audit: Path | None = None,
        approval_timeout_s: float = 0.0,
    ) -> Wired:
        stack = compose_monitor(
            policy_path or policy_dir / "rmm.yaml",
            audit or audit_path,
            approval_timeout_s=approval_timeout_s,
            approvals=ObservableQueue(),
        )
        return stack  # type: ignore[return-value]

    return build


@pytest.fixture()
def wired(build_wired: Callable[..., Wired]) -> Wired:
    """The default wired monitor over the RMM policy. Unanswered gates time out immediately."""
    return build_wired()


@pytest.fixture()
def console() -> Callable[[MonitorStack], FlaskClient]:
    """Factory: a Flask test client over the production console wiring for a stack."""

    def make(stack: MonitorStack) -> FlaskClient:
        app = create_app(console_context(stack), console_users(CONSOLE_ENV), "integration-secret")
        app.config["TESTING"] = True
        return app.test_client()

    return make


@contextmanager
def loopback_to(service: MonitorService, capability: str = "cap") -> Iterator[LoopbackTransport]:
    """Serve `service` over a real loopback socket (ephemeral port) and yield a client."""
    server = LoopbackServer(service, host="127.0.0.1", port=0, capability=capability)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert wait_until_ready(server.base_url), "loopback server never became ready"
        yield LoopbackTransport(server.base_url, capability=capability, timeout=10.0)
    finally:
        server.shutdown()
        thread.join(timeout=10.0)


def script(*steps: tuple[str, dict[str, object]]) -> list[ModelResponse]:
    """A deterministic stub-model script: one tool proposal per step."""
    return [
        ModelResponse(proposal=ToolCallProposal(tool=tool, args=args), final_text=None)
        for tool, args in steps
    ]
