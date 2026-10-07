"""Console authentication, role-based access, CSRF, and session expiry (src/web/auth.py).

* every protected route redirects an anonymous or expired request to /login;
* bad password, unknown user, and empty credentials are rejected with 401 and no session;
* a viewer — or an authenticated session with a missing/forged role — cannot resolve approvals;
* every state-changing POST (approve/deny, logout) requires the session's CSRF token;
* sessions expire after 30 min idle or 8 h absolute, measured by an injected clock;
* stored credentials are hashes, never plaintext;
* operator edge cases: unknown decision verb, an approval id that no longer exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from flask.testing import FlaskClient
from werkzeug.test import TestResponse

from src.audit.writer import AuditWriter
from src.monitor.gate import ApprovalQueue, ApprovalStatus, PendingApproval
from src.monitor.session import RetentionConfig, SessionRegistry
from src.monitor.types import CallId, GateClass, Principal, SessionId, ToolCall
from src.policy.loader import load_policy
from src.web import ConsoleContext, Role, UserStore, create_app
from src.web.auth import DEFAULT_ABSOLUTE_TIMEOUT_S, DEFAULT_IDLE_TIMEOUT_S, current_role
from tests.web.conftest import FakeClock, csrf

REPO_ROOT = Path(__file__).resolve().parents[2]
RMM = REPO_ROOT / "policies" / "rmm.yaml"

PROTECTED_GETS = ["/", "/audit", "/approvals", "/policy", "/sequence"]


def gated_call() -> ToolCall:
    return ToolCall(
        tool="export_records",
        args={"to": "x"},
        session_id=SessionId("s-1"),
        principal=Principal("client-1"),
        call_id=CallId("c1"),
        timestamp=0.0,
    )


@pytest.fixture()
def queue() -> ApprovalQueue:
    return ApprovalQueue()


@pytest.fixture()
def pending(queue: ApprovalQueue) -> PendingApproval:
    return queue.enqueue(gated_call(), GateClass.DATA_EXPORT)


@pytest.fixture()
def clock() -> FakeClock:
    return FakeClock()


def make_context(tmp_path: Path, queue: ApprovalQueue) -> ConsoleContext:
    return ConsoleContext(
        approvals=queue,
        sessions=SessionRegistry(AuditWriter(tmp_path / "sessions.jsonl"), RetentionConfig()),
        policy=load_policy(RMM),
        audit_path=tmp_path / "audit.jsonl",  # deliberately never written: "no log yet" path
    )


@pytest.fixture()
def client(tmp_path: Path, queue: ApprovalQueue, clock: FakeClock) -> FlaskClient:
    users = UserStore()
    users.add("op", "op-pass", Role.OPERATOR)
    users.add("viewer", "viewer-pass", Role.VIEWER)
    app = create_app(make_context(tmp_path, queue), users, secret_key="test-secret", clock=clock)
    app.config["TESTING"] = True
    app.config["PROPAGATE_EXCEPTIONS"] = False  # observe a server error as a 500, not a raise
    return app.test_client()


def login_response(client: FlaskClient, username: str, password: str) -> TestResponse:
    return client.post("/login", data={"username": username, "password": password})


def login(client: FlaskClient, username: str, password: str) -> int:
    return login_response(client, username, password).status_code


def plant_session(client: FlaskClient, clock: FakeClock, **fields: object) -> None:
    """Write a well-timed session directly, to probe checks that come after authentication."""
    with client.session_transaction() as sess:
        sess.update({"login_at": clock.now, "seen_at": clock.now, "csrf": "tok", **fields})


def approve(client: FlaskClient, pending: PendingApproval, token: str | None = None) -> int:
    data = {} if token is None else {"csrf_token": token}
    return client.post(f"/approvals/{pending.approval_id}/approve", data=data).status_code


# --- UserStore ----------------------------------------------------------------------------


def test_user_store_never_retains_plaintext_password() -> None:
    users = UserStore()
    users.add("op", "op-pass", Role.OPERATOR)
    stored = users._users["op"].password_hash
    assert "op-pass" not in stored


@pytest.mark.parametrize(
    ("username", "password"),
    [("op", "wrong"), ("nobody", "op-pass"), ("", ""), ("op", ""), ("OP", "op-pass")],
)
def test_user_store_verify_bad_credentials_returns_none(username: str, password: str) -> None:
    users = UserStore()
    users.add("op", "op-pass", Role.OPERATOR)
    assert users.verify(username, password) is None


def test_user_store_verify_good_credentials_returns_user_with_role() -> None:
    users = UserStore()
    users.add("op", "op-pass", Role.OPERATOR)
    user = users.verify("op", "op-pass")
    assert user is not None and user.role is Role.OPERATOR


# --- login required on every protected route ----------------------------------------------


@pytest.mark.parametrize("path", PROTECTED_GETS)
def test_protected_get_anonymous_redirects_to_login(client: FlaskClient, path: str) -> None:
    response = client.get(path)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_resolve_post_anonymous_redirects_and_leaves_pending(
    client: FlaskClient, queue: ApprovalQueue, pending: PendingApproval, decision: str
) -> None:
    response = client.post(f"/approvals/{pending.approval_id}/{decision}")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")
    assert queue.list_pending() == (pending,)


@pytest.mark.parametrize("path", PROTECTED_GETS)
def test_protected_get_viewer_is_allowed(client: FlaskClient, path: str) -> None:
    login(client, "viewer", "viewer-pass")
    assert client.get(path).status_code == 200


def test_session_without_timestamps_is_treated_as_anonymous(client: FlaskClient) -> None:
    with client.session_transaction() as sess:
        sess["user"] = "op"
        sess["role"] = Role.OPERATOR.value
    assert client.get("/").status_code == 302


# --- bad credentials ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("username", "password"),
    [("op", "wrong"), ("nobody", "x"), ("", ""), ("op", "OP-PASS")],
)
def test_login_bad_credentials_returns_401_and_sets_no_session(
    client: FlaskClient, username: str, password: str
) -> None:
    assert login(client, username, password) == 401
    with client.session_transaction() as sess:
        assert "user" not in sess
    assert client.get("/").status_code == 302


def test_login_missing_form_fields_returns_401(client: FlaskClient) -> None:
    assert client.post("/login", data={}).status_code == 401


def test_login_get_when_already_authenticated_redirects_to_dashboard(client: FlaskClient) -> None:
    login(client, "op", "op-pass")
    response = client.get("/login")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_login_success_replaces_any_prior_session_state(client: FlaskClient) -> None:
    with client.session_transaction() as sess:
        sess["role"] = Role.OPERATOR.value  # planted before authenticating as a viewer
        sess["stale"] = "x"
        sess["csrf"] = "attacker-chosen"
    login(client, "viewer", "viewer-pass")
    with client.session_transaction() as sess:
        assert sess["role"] == Role.VIEWER.value
        assert "stale" not in sess
        assert sess["csrf"] != "attacker-chosen"  # no session/CSRF fixation


# --- role enforcement on the only acting route -------------------------------------------


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_resolve_viewer_is_forbidden_and_leaves_pending(
    client: FlaskClient, queue: ApprovalQueue, pending: PendingApproval, decision: str
) -> None:
    login(client, "viewer", "viewer-pass")
    response = client.post(
        f"/approvals/{pending.approval_id}/{decision}", data={"csrf_token": csrf(client)}
    )
    assert response.status_code == 403
    assert queue.list_pending() == (pending,)


def test_resolve_session_with_user_but_no_role_is_forbidden(
    client: FlaskClient, clock: FakeClock, queue: ApprovalQueue, pending: PendingApproval
) -> None:
    plant_session(client, clock, user="op")
    assert approve(client, pending, "tok") == 403
    assert queue.list_pending() == (pending,)


@pytest.mark.parametrize("role", ["admin", "", "OPERATOR", 1])
def test_resolve_session_with_unknown_role_value_is_forbidden(
    client: FlaskClient,
    clock: FakeClock,
    queue: ApprovalQueue,
    pending: PendingApproval,
    role: object,
) -> None:
    plant_session(client, clock, user="op", role=role)
    assert approve(client, pending, "tok") == 403
    assert queue.list_pending() == (pending,)


def test_resolve_with_forged_cookie_signed_by_other_key_is_not_authenticated(
    tmp_path: Path, queue: ApprovalQueue, pending: PendingApproval
) -> None:
    context = make_context(tmp_path, queue)
    attacker_app = create_app(context, UserStore(), secret_key="attacker-key")
    real_app = create_app(context, UserStore(), secret_key="real-key")
    forger = attacker_app.test_client()
    with forger.session_transaction() as sess:
        sess.update(
            {"user": "op", "role": "operator", "login_at": 9e12, "seen_at": 9e12, "csrf": "t"}
        )
    forged_cookie = forger.get_cookie("session")
    assert forged_cookie is not None
    victim = real_app.test_client()
    victim.set_cookie("session", forged_cookie.value)
    assert approve(victim, pending, "t") == 302
    assert queue.list_pending() == (pending,)


# --- CSRF ---------------------------------------------------------------------------------


@pytest.mark.parametrize("token", [None, "", "wrong-token"], ids=["missing", "empty", "wrong"])
def test_resolve_operator_without_valid_csrf_token_is_forbidden(
    client: FlaskClient, queue: ApprovalQueue, pending: PendingApproval, token: str | None
) -> None:
    login(client, "op", "op-pass")
    assert approve(client, pending, token) == 403
    assert queue.list_pending() == (pending,)


def test_resolve_with_token_from_a_previous_session_is_forbidden(
    client: FlaskClient, queue: ApprovalQueue, pending: PendingApproval
) -> None:
    login(client, "op", "op-pass")
    old = csrf(client)
    client.post("/logout", data={"csrf_token": old})
    login(client, "op", "op-pass")
    assert csrf(client) != old  # rotated on every login
    assert approve(client, pending, old) == 403
    assert queue.list_pending() == (pending,)


def test_approvals_page_embeds_the_session_csrf_token(
    client: FlaskClient, pending: PendingApproval
) -> None:
    login(client, "op", "op-pass")
    page = client.get("/approvals").data.decode()
    assert f'name="csrf_token" value="{csrf(client)}"' in page


def test_logout_without_csrf_token_keeps_the_session(client: FlaskClient) -> None:
    login(client, "op", "op-pass")
    client.post("/logout", data={})
    assert client.get("/approvals").status_code == 200


def test_logout_via_get_is_not_allowed(client: FlaskClient) -> None:
    login(client, "op", "op-pass")
    assert client.get("/logout").status_code == 405
    assert client.get("/approvals").status_code == 200


def test_logout_then_protected_route_requires_login_again(client: FlaskClient) -> None:
    login(client, "op", "op-pass")
    client.post("/logout", data={"csrf_token": csrf(client)})
    assert client.get("/approvals").status_code == 302


# --- session expiry (injected clock) ------------------------------------------------------


def test_session_idle_just_under_limit_is_still_valid(
    client: FlaskClient, clock: FakeClock
) -> None:
    login(client, "viewer", "viewer-pass")
    clock.advance(DEFAULT_IDLE_TIMEOUT_S - 1)
    assert client.get("/").status_code == 200


def test_session_idle_past_limit_redirects_to_login_and_is_cleared(
    client: FlaskClient, clock: FakeClock
) -> None:
    login(client, "viewer", "viewer-pass")
    clock.advance(DEFAULT_IDLE_TIMEOUT_S + 1)
    assert client.get("/").status_code == 302
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_session_activity_refreshes_the_idle_timer(client: FlaskClient, clock: FakeClock) -> None:
    login(client, "viewer", "viewer-pass")
    for _ in range(3):
        clock.advance(DEFAULT_IDLE_TIMEOUT_S - 60)
        assert client.get("/").status_code == 200


def test_session_absolute_limit_expires_even_an_active_session(
    client: FlaskClient, clock: FakeClock
) -> None:
    login(client, "viewer", "viewer-pass")
    step = DEFAULT_IDLE_TIMEOUT_S - 60
    while clock.now + step < 1_000_000.0 + DEFAULT_ABSOLUTE_TIMEOUT_S:
        clock.advance(step)
        assert client.get("/").status_code == 200
    clock.advance(step)
    assert client.get("/").status_code == 302


def test_expired_operator_session_cannot_resolve_even_with_valid_token(
    client: FlaskClient, clock: FakeClock, queue: ApprovalQueue, pending: PendingApproval
) -> None:
    login(client, "op", "op-pass")
    token = csrf(client)
    clock.advance(DEFAULT_IDLE_TIMEOUT_S + 1)
    assert approve(client, pending, token) == 302
    assert queue.list_pending() == (pending,)


def test_custom_idle_timeout_is_honoured(
    tmp_path: Path, queue: ApprovalQueue, clock: FakeClock
) -> None:
    users = UserStore()
    users.add("viewer", "viewer-pass", Role.VIEWER)
    app = create_app(
        make_context(tmp_path, queue), users, secret_key="k", idle_timeout_s=10, clock=clock
    )
    client = app.test_client()
    login(client, "viewer", "viewer-pass")
    clock.advance(11)
    assert client.get("/").status_code == 302


def test_session_cookie_is_httponly_and_samesite_lax(client: FlaskClient) -> None:
    cookie = login_response(client, "op", "op-pass").headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


# --- operator edge cases ------------------------------------------------------------------


def test_resolve_unknown_decision_verb_does_not_resolve(
    client: FlaskClient, queue: ApprovalQueue, pending: PendingApproval
) -> None:
    login(client, "op", "op-pass")
    response = client.post(
        f"/approvals/{pending.approval_id}/maybe",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert b"Unknown decision" in response.data
    assert queue.list_pending() == (pending,)


def test_resolve_vanished_approval_id_flashes_not_available(client: FlaskClient) -> None:
    login(client, "op", "op-pass")
    response = client.post(
        "/approvals/appr-gone/approve", data={"csrf_token": csrf(client)}, follow_redirects=True
    )
    assert response.status_code == 200
    assert b"no longer available" in response.data


def test_resolve_operator_approve_records_status(
    client: FlaskClient, queue: ApprovalQueue, pending: PendingApproval
) -> None:
    login(client, "op", "op-pass")
    assert approve(client, pending, csrf(client)) == 302
    record = queue.get(pending.approval_id)
    assert record is not None and record.status is ApprovalStatus.APPROVED
    assert queue.list_pending() == ()


def test_resolve_get_method_is_not_allowed(
    client: FlaskClient, queue: ApprovalQueue, pending: PendingApproval
) -> None:
    login(client, "op", "op-pass")
    assert client.get(f"/approvals/{pending.approval_id}/approve").status_code == 405
    assert queue.list_pending() == (pending,)


def test_audit_view_with_no_log_file_yet_renders_empty(client: FlaskClient) -> None:
    login(client, "viewer", "viewer-pass")
    assert client.get("/audit").status_code == 200


def test_current_role_outside_session_values_maps_none(client: FlaskClient) -> None:
    with client.application.test_request_context():
        assert current_role() is None
