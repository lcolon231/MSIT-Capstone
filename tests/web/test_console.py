"""Operator console — issue #14 / T4.2.

Login + session auth, role-based access (operator can approve/deny, viewer is read-only), the
live decision feed, the pending-approvals actions, the policy viewer, and the sequence-state
inspector — all exercised through the Flask test client (no browser needed).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from flask.testing import FlaskClient

from src.audit.writer import AuditWriter, decision_event
from src.monitor.gate import ApprovalQueue
from src.monitor.session import RetentionConfig, SessionRegistry
from src.monitor.types import (
    CallId,
    ChainProgress,
    Decision,
    GateClass,
    Principal,
    SequenceState,
    SessionId,
    SubjectKey,
    ToolCall,
)
from src.policy.loader import load_policy
from src.transport.contract import Verdict
from src.web import ConsoleContext, Role, UserStore, create_app

REPO_ROOT = Path(__file__).resolve().parents[2]
BANKING = REPO_ROOT / "policies" / "banking.yaml"


def make_call(tool: str, **args: object) -> ToolCall:
    return ToolCall(
        tool=tool,
        args=args,
        session_id=SessionId("s-abc123def456"),
        principal=Principal("acct-1"),
        call_id=CallId("c1"),
        timestamp=1000.0,
    )


@pytest.fixture()
def context(tmp_path: Path) -> ConsoleContext:
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditWriter(audit_path)
    audit.append(decision_event(make_call("get_balance"), Decision(Verdict.ALLOW, "banking.get_balance.allow", "ok")))
    audit.append(decision_event(make_call("transfer_funds", to="acme-1", amount=500), Decision(Verdict.GATE, "banking.transfer_funds.gate", "gated")))

    sessions = SessionRegistry(audit, RetentionConfig())
    key = SubjectKey(SessionId("s-abc123def456"), Principal("acct-1"))
    sessions.commit(
        SessionId("s-abc123def456"),
        SequenceState(progress={key: (ChainProgress(chain="recon_add_drain", node="S3_PAYEE_ADDED", bindings={"added_payee_id": "deadbeef"}, updated_at=1000.0),)}),
    )

    approvals = ApprovalQueue()
    approvals.enqueue(make_call("transfer_funds", to="acme-1", amount=500), GateClass.FUND_TRANSFER)

    return ConsoleContext(
        approvals=approvals,
        sessions=sessions,
        policy=load_policy(BANKING),
        audit_path=audit_path,
        policy_source=BANKING.read_text(encoding="utf-8"),
    )


@pytest.fixture()
def client(context: ConsoleContext) -> FlaskClient:
    users = UserStore()
    users.add("op", "op-pass", Role.OPERATOR)
    users.add("viewer", "viewer-pass", Role.VIEWER)
    app = create_app(context, users, secret_key="test-secret")
    app.config["TESTING"] = True
    return app.test_client()


def login(client: FlaskClient, username: str, password: str):
    return client.post("/login", data={"username": username, "password": password})


# --- auth ---------------------------------------------------------------------------------


def test_dashboard_requires_login(client: FlaskClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_login_with_bad_credentials_is_rejected(client: FlaskClient) -> None:
    resp = login(client, "op", "wrong")
    assert resp.status_code == 401
    assert b"Invalid" in resp.data


def test_login_then_dashboard_shows_decisions(client: FlaskClient) -> None:
    login(client, "op", "op-pass")
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"get_balance" in resp.data
    assert b"transfer_funds" in resp.data


def test_logout_clears_session(client: FlaskClient) -> None:
    login(client, "op", "op-pass")
    client.get("/logout")
    assert client.get("/").status_code == 302  # back to needing login


# --- RBAC: approvals ----------------------------------------------------------------------


def test_operator_can_approve_and_it_resolves_the_queue(client: FlaskClient, context: ConsoleContext) -> None:
    login(client, "op", "op-pass")
    approval_id = context.approvals.list_pending()[0].approval_id
    resp = client.post(f"/approvals/{approval_id}/approve")
    assert resp.status_code == 302
    assert context.approvals.list_pending() == ()  # no longer pending
    assert context.approvals.get(approval_id).status.value == "approved"


def test_operator_sees_action_buttons(client: FlaskClient) -> None:
    login(client, "op", "op-pass")
    resp = client.get("/approvals")
    assert b"Approve" in resp.data and b"Deny" in resp.data


def test_viewer_cannot_see_action_buttons(client: FlaskClient) -> None:
    login(client, "viewer", "viewer-pass")
    resp = client.get("/approvals")
    assert resp.status_code == 200
    assert b"read-only" in resp.data
    assert b"Approve" not in resp.data


def test_viewer_is_forbidden_from_resolving(client: FlaskClient, context: ConsoleContext) -> None:
    login(client, "viewer", "viewer-pass")
    approval_id = context.approvals.list_pending()[0].approval_id
    resp = client.post(f"/approvals/{approval_id}/approve")
    assert resp.status_code == 403
    assert context.approvals.list_pending()  # still pending — the viewer could not act


def test_anonymous_post_to_resolve_redirects_to_login(client: FlaskClient) -> None:
    resp = client.post("/approvals/whatever/approve")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


# --- policy viewer + sequence inspector + audit -------------------------------------------


def test_policy_viewer_renders_rules_and_chain(client: FlaskClient) -> None:
    login(client, "viewer", "viewer-pass")
    resp = client.get("/policy")
    assert resp.status_code == 200
    assert b"banking.transfer_funds.gate" in resp.data
    assert b"recon_add_drain" in resp.data


def test_sequence_inspector_shows_partway_chain(client: FlaskClient) -> None:
    login(client, "viewer", "viewer-pass")
    resp = client.get("/sequence")
    assert resp.status_code == 200
    assert b"recon_add_drain" in resp.data
    assert b"S3_PAYEE_ADDED" in resp.data
    assert b"added_payee_id" in resp.data


def test_audit_view_lists_events(client: FlaskClient) -> None:
    login(client, "op", "op-pass")
    resp = client.get("/audit")
    assert resp.status_code == 200
    assert b"decision" in resp.data
