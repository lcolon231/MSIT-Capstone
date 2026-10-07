"""Console routes — login/session, dashboard, approvals, policy viewer, sequence inspector.

The console only ever OBSERVES the monitor (audit log, live sequence state, loaded policy) and
resolves gated approvals through the shared queue. It has no route that executes a tool or edits
policy — enforcement stays entirely in the monitor process.
"""

from __future__ import annotations

from pathlib import Path

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask.typing import ResponseReturnValue

from src.audit.events import ApprovalResolutionEvent, AuditEvent, DecisionEvent
from src.audit.replay import replay
from src.monitor.gate import ApprovalId
from src.web.auth import (
    CSRF_FIELD,
    Role,
    UserStore,
    current_role,
    login_required,
    requires_role,
    start_session,
)
from src.web.context import ConsoleContext

bp = Blueprint("console", __name__)


def _context() -> ConsoleContext:
    return current_app.config["CONSOLE"]  # type: ignore[no-any-return]


def _users() -> UserStore:
    return current_app.config["USERS"]  # type: ignore[no-any-return]


def _recent_events(path: Path, limit: int = 100) -> list[AuditEvent]:
    """Newest-first audit events, or an empty list if the log does not exist yet."""
    if not Path(path).exists():
        return []
    events = list(replay(path))
    events.reverse()
    return events[:limit]


# --- auth ---------------------------------------------------------------------------------


@bp.route("/login", methods=["GET", "POST"])
def login() -> ResponseReturnValue:
    if request.method == "POST":
        user = _users().verify(request.form.get("username", ""), request.form.get("password", ""))
        if user is None:
            return render_template("login.html", error="Invalid username or password"), 401
        start_session(user.username, user.role)
        return redirect(url_for("console.dashboard"))
    if "user" in session:
        return redirect(url_for("console.dashboard"))
    return render_template("login.html", error=None)


@bp.route("/logout", methods=["POST"])
def logout() -> ResponseReturnValue:
    """POST-only and CSRF-checked, so another site cannot force an operator out. A request
    without the session's token leaves the session alone."""
    expected = session.get("csrf")
    if isinstance(expected, str) and request.form.get(CSRF_FIELD) == expected:
        session.clear()
    return redirect(url_for("console.login"))


# --- dashboard + audit --------------------------------------------------------------------


@bp.route("/")
@login_required
def dashboard() -> ResponseReturnValue:
    ctx = _context()
    events = _recent_events(ctx.audit_path)
    decisions = [e for e in events if isinstance(e, DecisionEvent)][:20]
    resolutions = [e for e in events if isinstance(e, ApprovalResolutionEvent)][:20]
    return render_template(
        "dashboard.html",
        decisions=decisions,
        resolutions=resolutions,
        pending_count=len(ctx.approvals.list_pending()),
    )


@bp.route("/audit")
@login_required
def audit() -> ResponseReturnValue:
    return render_template("audit.html", events=_recent_events(_context().audit_path))


# --- approvals (operator can act; viewer read-only) ---------------------------------------


@bp.route("/approvals")
@login_required
def approvals() -> ResponseReturnValue:
    pending = _context().approvals.list_pending()
    can_act = current_role() is Role.OPERATOR
    return render_template("approvals.html", pending=pending, can_act=can_act)


@bp.route("/approvals/<approval_id>/<decision>", methods=["POST"])
@requires_role(Role.OPERATOR)
def resolve_approval(approval_id: str, decision: str) -> ResponseReturnValue:
    if decision not in ("approve", "deny"):
        flash("Unknown decision.", "error")
        return redirect(url_for("console.approvals"))
    operator = session.get("user", "unknown")
    try:
        record = _context().approvals.resolve(
            ApprovalId(approval_id), approved=(decision == "approve"), operator=operator
        )
    except KeyError:
        flash("That approval is no longer available.", "error")
        return redirect(url_for("console.approvals"))
    flash(f"{record.tool} {record.status.value} by {operator}.", "ok")
    return redirect(url_for("console.approvals"))


# --- policy viewer ------------------------------------------------------------------------


@bp.route("/policy")
@login_required
def policy() -> ResponseReturnValue:
    ctx = _context()
    return render_template("policy.html", policy=ctx.policy, source=ctx.policy_source)


# --- sequence-state inspector -------------------------------------------------------------


@bp.route("/sequence")
@login_required
def sequence() -> ResponseReturnValue:
    state = _context().sessions.live_state()
    rows = []
    for subject, chains in state.progress.items():
        for chain in chains:
            rows.append(
                {
                    "session_id": subject.session_id,
                    "principal": subject.principal,
                    "chain": chain.chain,
                    "node": chain.node,
                    "bindings": ", ".join(sorted(chain.bindings)) or "—",
                    "updated_at": chain.updated_at,
                }
            )
    return render_template("sequence.html", rows=rows)
