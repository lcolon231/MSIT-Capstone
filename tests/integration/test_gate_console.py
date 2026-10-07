"""Scenario 4 — the human gate driven through the real web console.

The agent's export to the pre-approved destination is a per-call GATE (data_export). The
monitor blocks on the shared approval queue; the call appears on /approvals; an operator logs in
and approves through the Flask test client; the call then executes; and both the GATE decision
and the approval resolution are in the audit log. Waiting is event-driven (the queue signals on
enqueue; the agent thread is joined) — no sleeps.
"""

from __future__ import annotations

import re
import threading
from typing import Callable

import pytest
from flask.testing import FlaskClient

from src.agent.loop import Agent, AgentRun
from src.agent.model import StubModel
from src.audit.events import ApprovalResolutionEvent, DecisionEvent
from src.audit.replay import replay
from src.monitor.gate import ApprovalStatus
from src.transport.contract import ResultStatus, Verdict
from src.transport.inprocess import InProcessTransport
from tests.integration.conftest import OPERATOR, VIEWER, Wired, script

pytestmark = pytest.mark.integration

WAIT_S = 10.0  # upper bound only; every wait returns as soon as its event fires
EXPORT = script(("export_records", {"to": "approved-baa-backup", "count": 12}))


class AgentThread(threading.Thread):
    def __init__(self, wired: Wired) -> None:
        super().__init__(daemon=True)
        self._wired = wired
        self.result: AgentRun | None = None

    def run(self) -> None:
        agent = Agent(StubModel(EXPORT), InProcessTransport(self._wired.service))
        self.result = agent.run_traced("export the monthly backup")


def start_gated_export(build_wired: Callable[..., Wired]) -> tuple[Wired, AgentThread]:
    # A long approval timeout: the test, not the clock, decides when the gate resolves.
    w = build_wired(approval_timeout_s=60.0)
    agent = AgentThread(w)
    agent.start()
    assert w.approvals.enqueued.wait(WAIT_S), "GATE never reached the approval queue"
    return w, agent


def login(client: FlaskClient, user: tuple[str, str]) -> None:
    response = client.post("/login", data={"username": user[0], "password": user[1]})
    assert response.status_code == 302


def form_token(client: FlaskClient) -> str:
    """The CSRF token exactly as a browser would submit it: scraped from the approvals form."""
    match = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/approvals").get_data(True))
    assert match, "approvals page rendered no CSRF token"
    return match.group(1)


def finish(agent: AgentThread) -> AgentRun:
    agent.join(WAIT_S)
    assert not agent.is_alive(), "agent never unblocked after the operator acted"
    assert agent.result is not None
    return agent.result


def test_gate_operator_approves_via_console_then_call_executes_and_both_events_audited(
    build_wired: Callable[..., Wired], console: Callable[[Wired], FlaskClient]
) -> None:
    w, agent = start_gated_export(build_wired)
    client = console(w)
    login(client, OPERATOR)

    (pending,) = w.approvals.list_pending()
    page = client.get("/approvals")
    assert page.status_code == 200
    assert pending.approval_id.encode() in page.data
    assert b"export_records" in page.data

    client.post(
        f"/approvals/{pending.approval_id}/approve", data={"csrf_token": form_token(client)}
    )
    agent_run = finish(agent)

    ((_, result),) = agent_run.steps
    assert result.status is ResultStatus.EXECUTED
    assert result.decision.verdict is Verdict.GATE  # gated, then approved — not a per-call ALLOW
    assert result.payload is not None

    events = list(replay(w.audit_path))
    gate_decisions = [e for e in events if isinstance(e, DecisionEvent)]
    resolutions = [e for e in events if isinstance(e, ApprovalResolutionEvent)]
    assert [(d.tool, d.verdict, d.rule_id) for d in gate_decisions] == [
        ("export_records", Verdict.GATE, "rmm.export_records.gate")
    ]
    assert [(r.approval_id, r.resolution) for r in resolutions] == [
        (pending.approval_id, "approved")
    ]
    assert resolutions[0].call_id == gate_decisions[0].call_id
    assert events.index(gate_decisions[0]) < events.index(resolutions[0])


def test_gate_operator_denies_via_console_then_call_never_executes(
    build_wired: Callable[..., Wired], console: Callable[[Wired], FlaskClient]
) -> None:
    w, agent = start_gated_export(build_wired)
    client = console(w)
    login(client, OPERATOR)
    (pending,) = w.approvals.list_pending()
    client.post(f"/approvals/{pending.approval_id}/deny", data={"csrf_token": form_token(client)})
    ((_, result),) = finish(agent).steps
    assert result.status is ResultStatus.DENIED
    assert result.payload is None
    resolutions = [
        e.resolution for e in replay(w.audit_path) if isinstance(e, ApprovalResolutionEvent)
    ]
    assert resolutions == ["denied"]


def test_gate_viewer_cannot_approve_and_call_stays_blocked(
    build_wired: Callable[..., Wired], console: Callable[[Wired], FlaskClient]
) -> None:
    w, agent = start_gated_export(build_wired)
    client = console(w)
    login(client, VIEWER)
    (pending,) = w.approvals.list_pending()
    with client.session_transaction() as sess:
        token = sess["csrf"]  # the viewer's own valid token: refusal is by role, not CSRF
    response = client.post(f"/approvals/{pending.approval_id}/approve", data={"csrf_token": token})
    assert response.status_code == 403
    assert agent.is_alive()
    assert w.approvals.list_pending() == (pending,)
    # Clean up: an operator denies so the agent thread ends inside the test.
    w.approvals.resolve(pending.approval_id, approved=False, operator="cleanup")
    ((_, result),) = finish(agent).steps
    assert result.status is ResultStatus.DENIED


def test_gate_decision_shows_on_dashboard_feed_while_pending(
    build_wired: Callable[..., Wired], console: Callable[[Wired], FlaskClient]
) -> None:
    w, agent = start_gated_export(build_wired)
    client = console(w)
    login(client, VIEWER)
    page = client.get("/")
    assert b"rmm.export_records.gate" in page.data
    (pending,) = w.approvals.list_pending()
    w.approvals.resolve(pending.approval_id, approved=False, operator="cleanup")
    finish(agent)
    assert w.approvals.get(pending.approval_id).status is ApprovalStatus.DENIED  # type: ignore[union-attr]


# --- the deployed shape: loopback monitor + in-process console, over real sockets ----------


def test_console_over_http_releases_a_call_blocked_on_the_loopback_monitor(
    build_wired: Callable[..., Wired],
) -> None:
    import http.cookiejar
    import urllib.parse
    import urllib.request

    from src.monitor_server import start_console
    from tests.integration.conftest import CONSOLE_ENV, loopback_to

    w = build_wired(approval_timeout_s=60.0)
    results: list[AgentRun] = []
    with loopback_to(w.service) as transport:
        agent = threading.Thread(
            target=lambda: results.append(Agent(StubModel(EXPORT), transport).run_traced("t")),
            daemon=True,
        )
        agent.start()
        assert w.approvals.enqueued.wait(WAIT_S), "GATE never reached the approval queue"
        console = start_console(w, "127.0.0.1", 0, CONSOLE_ENV)
        try:
            base = f"http://127.0.0.1:{console.server_port}"
            browser = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )

            def post(path: str, form: dict[str, str]) -> str:
                body = urllib.parse.urlencode(form).encode()
                return browser.open(base + path, data=body, timeout=WAIT_S).read().decode()

            post("/login", {"username": OPERATOR[0], "password": OPERATOR[1]})
            page = browser.open(base + "/approvals", timeout=WAIT_S).read().decode()
            token = re.search(r'name="csrf_token" value="([^"]+)"', page)
            assert token, "approvals page rendered no CSRF token"
            (pending,) = w.approvals.list_pending()
            post(f"/approvals/{pending.approval_id}/approve", {"csrf_token": token.group(1)})
            agent.join(WAIT_S)
        finally:
            console.shutdown()
    assert not agent.is_alive()
    ((_, result),) = results[0].steps
    assert result.status is ResultStatus.EXECUTED
    assert result.decision.verdict is Verdict.GATE
