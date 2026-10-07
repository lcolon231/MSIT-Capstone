"""Loopback monitor process entry point (src/monitor_server.py), with the HTTP server faked.

* profile selection builds the RMM or eval monitor with the requested policy/audit/timeout;
* the bootstrap capability comes only from the environment, never argv;
* `--approve-gates` attaches the auto-approver only for the eval profile;
* the server is always shut down, and the auto-approver stopped, when serving ends.
"""

from __future__ import annotations

import argparse
import threading
from pathlib import Path
from typing import Any

import pytest

import src.monitor_server as server_mod
from src.monitor.gate import ApprovalQueue, ApprovalStatus
from src.monitor.types import CallId, GateClass, Principal, SessionId, ToolCall


class FakeServer:
    instances: list["FakeServer"] = []

    def __init__(self, service: Any, host: str, port: int, capability: str | None) -> None:
        self.service, self.host, self.port, self.capability = service, host, port, capability
        self.shut = False
        FakeServer.instances.append(self)

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def serve_forever(self) -> None:
        raise KeyboardInterrupt  # simulate Ctrl-C straight away

    def shutdown(self) -> None:
        self.shut = True


@pytest.fixture()
def fake_server(monkeypatch: pytest.MonkeyPatch) -> type[FakeServer]:
    FakeServer.instances = []
    monkeypatch.setattr(server_mod, "LoopbackServer", FakeServer)
    return FakeServer


def ns(**kwargs: Any) -> argparse.Namespace:
    defaults = {"profile": "rmm", "policy": None, "audit": "a.jsonl", "approval_timeout": 2.0}
    return argparse.Namespace(**{**defaults, **kwargs})


# --- _build_service -----------------------------------------------------------------------


class FakeStack:
    service = "svc"


def fake_compose(calls: list[tuple[Any, ...]]) -> Any:
    def compose(*args: Any) -> FakeStack:
        calls.append(args)
        return FakeStack()

    return compose


def test_build_service_rmm_profile_returns_stack_and_no_auto_approve_queue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(server_mod, "compose_monitor", fake_compose(calls))
    service, queue, stack = server_mod._build_service(ns())
    assert (service, queue, isinstance(stack, FakeStack)) == ("svc", None, True)
    assert calls == [(Path("policies/rmm.yaml"), Path("a.jsonl"), 2.0)]


def test_build_service_rmm_profile_uses_explicit_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(server_mod, "compose_monitor", fake_compose(calls))
    server_mod._build_service(ns(policy="p.yaml", approval_timeout=0.5))
    assert calls == [(Path("p.yaml"), Path("a.jsonl"), 0.5)]


@pytest.mark.parametrize(
    ("policy", "expected"),
    [(None, (Path("a.jsonl"),)), ("p.yaml", (Path("a.jsonl"), Path("p.yaml"), 2.0))],
)
def test_build_service_eval_profile_returns_service_and_queue(
    monkeypatch: pytest.MonkeyPatch, policy: str | None, expected: tuple[Any, ...]
) -> None:
    calls: list[tuple[Any, ...]] = []

    def fake_eval(*args: Any, **kwargs: Any) -> tuple[str, str]:
        calls.append(args)
        return "svc", "queue"

    monkeypatch.setattr(server_mod, "build_eval_monitor", fake_eval)
    assert server_mod._build_service(ns(profile="eval", policy=policy)) == ("svc", "queue", None)
    assert calls == [expected]


# --- main ---------------------------------------------------------------------------------


def test_main_reads_capability_from_env_and_shuts_down(
    fake_server: type[FakeServer], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(server_mod.CAPABILITY_ENV, "cap-123")
    code = server_mod.main(["--audit", str(tmp_path / "a.jsonl"), "--port", "0"])
    (instance,) = fake_server.instances
    assert code == 0
    assert instance.capability == "cap-123"
    assert instance.shut


def test_main_without_env_capability_passes_none(
    fake_server: type[FakeServer], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(server_mod.CAPABILITY_ENV, raising=False)
    server_mod.main(["--audit", str(tmp_path / "a.jsonl")])
    assert fake_server.instances[0].capability is None


def test_main_ready_banner_prints_base_url(
    fake_server: type[FakeServer], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    server_mod.main(["--audit", str(tmp_path / "a.jsonl"), "--port", "9", "--ready-banner"])
    assert capsys.readouterr().out.strip() == "READY http://127.0.0.1:9"


@pytest.mark.parametrize(("profile", "attached"), [("eval", True), ("rmm", False)])
def test_main_approve_gates_attaches_auto_approver_only_for_eval(
    fake_server: type[FakeServer],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    profile: str,
    attached: bool,
) -> None:
    stops: list[threading.Event] = []
    monkeypatch.setattr(server_mod, "_auto_approver", lambda q, stop: stops.append(stop))
    server_mod.main(["--profile", profile, "--audit", str(tmp_path / "a.jsonl"), "--approve-gates"])
    assert bool(stops) is attached
    assert all(stop.is_set() for stop in stops)  # stopped when serving ends


# --- _auto_approver -----------------------------------------------------------------------


def test_auto_approver_approves_pending_gate_and_stops_on_event() -> None:
    queue = ApprovalQueue()
    call = ToolCall("export_records", {}, SessionId("s"), Principal("p"), CallId("c"), 0.0)
    pending = queue.enqueue(call, GateClass.DATA_EXPORT)
    stop = threading.Event()
    thread = server_mod._auto_approver(queue, stop)
    try:
        # Blocks on the queue's own Event — returns as soon as the approver resolves it.
        assert queue.await_resolution(pending.approval_id, 10.0) is ApprovalStatus.APPROVED
    finally:
        stop.set()
        thread.join(timeout=10.0)
    assert not thread.is_alive()


# --- in-process operator console (--console-port) -----------------------------------------


@pytest.fixture()
def stack(tmp_path: Path) -> Any:
    from src.composition import compose_monitor

    repo = Path(__file__).resolve().parents[1]
    return compose_monitor(repo / "policies" / "rmm.yaml", tmp_path / "a.jsonl")


def test_console_users_requires_op_pass() -> None:
    with pytest.raises(SystemExit):
        server_mod.console_users({})


def test_console_users_builds_operator_and_optional_viewer() -> None:
    from src.web import Role

    users = server_mod.console_users({"OP_PASS": "p", "VIEW_PASS": "v"})
    op, viewer = users.verify("operator", "p"), users.verify("viewer", "v")
    assert op is not None and op.role is Role.OPERATOR
    assert viewer is not None and viewer.role is Role.VIEWER


def test_console_users_without_view_pass_has_no_viewer() -> None:
    users = server_mod.console_users({"OP_PASS": "p", "VIEW_USER": "v"})
    assert users.verify("v", "") is None


def test_console_context_shares_the_monitors_live_objects(stack: Any) -> None:
    context = server_mod.console_context(stack)
    assert context.approvals is stack.approvals
    assert context.sessions is stack.sessions
    assert context.policy is stack.policy
    assert context.audit_path == stack.audit_path
    assert "recon_register_exfil" in context.policy_source


def test_console_context_unreadable_policy_says_deny_all(tmp_path: Path) -> None:
    from src.composition import compose_monitor

    stack = compose_monitor(tmp_path / "missing.yaml", tmp_path / "a.jsonl")
    assert "DENY-ALL" in server_mod.console_context(stack).policy_source


def test_start_console_serves_app_on_requested_address(
    stack: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    started = threading.Event()
    seen: dict[str, Any] = {}

    class FakeWsgi:
        def serve_forever(self) -> None:
            started.set()

        def shutdown(self) -> None:
            pass

    def fake_make_server(host: str, port: int, app: Any, threaded: bool) -> FakeWsgi:
        seen.update(host=host, port=port, app=app, threaded=threaded)
        return FakeWsgi()

    monkeypatch.setattr(server_mod, "make_server", fake_make_server)
    server_mod.start_console(stack, "127.0.0.1", 5055, {"OP_PASS": "p"})
    assert started.wait(10.0)
    assert (seen["host"], seen["port"], seen["threaded"]) == ("127.0.0.1", 5055, True)
    assert seen["app"].config["CONSOLE"].approvals is stack.approvals


def test_main_console_port_rejected_for_eval_profile(fake_server: type[FakeServer]) -> None:
    with pytest.raises(SystemExit):
        server_mod.main(["--profile", "eval", "--console-port", "5000"])


def test_main_console_port_starts_and_stops_console(
    fake_server: type[FakeServer], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    consoles: list[Any] = []

    class FakeConsole:
        stopped = False

        def shutdown(self) -> None:
            self.stopped = True

    def fake_start(stack: Any, host: str, port: int, env: Any) -> FakeConsole:
        consoles.append((stack, port, FakeConsole()))
        return consoles[-1][2]

    monkeypatch.setattr(server_mod, "start_console", fake_start)
    server_mod.main(["--audit", str(tmp_path / "a.jsonl"), "--console-port", "5001"])
    ((stack, port, console),) = consoles
    assert port == 5001
    assert stack.service is fake_server.instances[0].service  # console and loopback share it
    assert console.stopped
