"""Console authentication and role-based access control (D5 operator surface).

Two roles:
  - ``operator`` — may approve / deny gated calls (the only role that can act);
  - ``viewer``   — read-only: dashboard, audit feed, policy, and sequence inspector.

Passwords are stored only as werkzeug hashes; the plaintext is never retained. Approval intent
still comes exclusively from an authenticated operator POST resolved by approval id — never from
an agent or a call's arguments (see gate.py).
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from enum import Enum
from functools import wraps
from typing import Any, Callable, Mapping, TypeVar

from flask import abort, current_app, redirect, request, session, url_for
from flask.typing import ResponseReturnValue
from werkzeug.security import check_password_hash, generate_password_hash

F = TypeVar("F", bound=Callable[..., Any])


class Role(str, Enum):
    OPERATOR = "operator"
    VIEWER = "viewer"


@dataclass(frozen=True)
class User:
    username: str
    password_hash: str
    role: Role


class UserStore:
    """In-memory operator/viewer accounts. Seeded at app construction (or from config)."""

    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    def add(self, username: str, password: str, role: Role) -> None:
        self._users[username] = User(username, generate_password_hash(password), role)

    def verify(self, username: str, password: str) -> User | None:
        """Return the user iff the password matches its stored hash; else None (fail-closed)."""
        user = self._users.get(username)
        if user is not None and check_password_hash(user.password_hash, password):
            return user
        return None


def users_from_env(env: Mapping[str, str]) -> UserStore:
    """Operator (required) and optional viewer accounts from the environment. There is no
    default password for either role: a console must never start with a guessable account.
    A missing ``OP_PASS`` stops startup with a message rather than falling back to a default."""
    op_pass = env.get("OP_PASS")
    if not op_pass:
        raise SystemExit("the operator console requires the OP_PASS environment variable")
    users = UserStore()
    users.add(env.get("OP_USER", "operator"), op_pass, Role.OPERATOR)
    view_pass = env.get("VIEW_PASS")
    if view_pass:
        users.add(env.get("VIEW_USER", "viewer"), view_pass, Role.VIEWER)
    return users


def current_role() -> Role | None:
    """The signed-in role, or None. An unrecognized value is treated as no role (→ 403), never
    as an error page — the request is refused either way, but cleanly."""
    try:
        return Role(session.get("role"))
    except ValueError:
        return None


# --- session lifetime ---------------------------------------------------------------------
#
# Two limits, both checked server-side against an injectable clock (app.config["CLOCK"]):
#   * idle    — no authenticated request for IDLE_TIMEOUT_S (default 30 min, matching the
#               monitor's own idle expiry, D12.3);
#   * absolute — AUTH_MAX_AGE_S after login (default 8 h), however active the session is.
# An expired session is cleared and treated exactly like an anonymous one.

DEFAULT_IDLE_TIMEOUT_S = 30 * 60
DEFAULT_ABSOLUTE_TIMEOUT_S = 8 * 60 * 60
CSRF_FIELD = "csrf_token"


def _now() -> float:
    clock: Callable[[], float] = current_app.config["CLOCK"]
    return clock()


def start_session(username: str, role: Role) -> None:
    """Begin a fresh authenticated session: new identity, new CSRF token, both timers reset.
    Clearing first prevents session fixation (nothing planted before login survives)."""
    session.clear()
    session.permanent = True
    now = _now()
    session["user"] = username
    session["role"] = role.value
    session["login_at"] = now
    session["seen_at"] = now
    session["csrf"] = secrets.token_urlsafe(32)


def _authenticated() -> bool:
    """True iff the session belongs to a signed-in user that has not expired. Refreshes the
    idle timer on success; clears the session on expiry."""
    if "user" not in session:
        return False
    now = _now()
    try:
        login_at = float(session["login_at"])
        seen_at = float(session["seen_at"])
    except (KeyError, TypeError, ValueError):
        session.clear()  # a session without valid timestamps is not a session
        return False
    idle = current_app.config["IDLE_TIMEOUT_S"]
    absolute = current_app.config["ABSOLUTE_TIMEOUT_S"]
    if now - seen_at > idle or now - login_at > absolute:
        session.clear()
        return False
    session["seen_at"] = now
    return True


def csrf_token() -> str:
    """The current session's CSRF token, for templates ("" when signed out)."""
    token = session.get("csrf")
    return token if isinstance(token, str) else ""


def _csrf_ok() -> bool:
    expected = session.get("csrf")
    supplied = request.form.get(CSRF_FIELD, "")
    return isinstance(expected, str) and bool(expected) and hmac.compare_digest(expected, supplied)


# --- decorators ---------------------------------------------------------------------------


def login_required(view: F) -> F:
    """Redirect unauthenticated or expired requests to the login page."""

    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> ResponseReturnValue:
        if not _authenticated():
            return redirect(url_for("console.login"))
        return view(*args, **kwargs)  # type: ignore[no-any-return]

    return wrapped  # type: ignore[return-value]


def requires_role(role: Role) -> Callable[[F], F]:
    """Gate a view behind a specific role. Anonymous or expired → login redirect;
    authenticated-but-wrong-role → 403; a state-changing request without the session's CSRF
    token → 403 (checked AFTER authentication, so it never leaks whether a session exists)."""

    def decorator(view: F) -> F:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> ResponseReturnValue:
            if not _authenticated():
                return redirect(url_for("console.login"))
            if current_role() is not role:
                abort(403)
            if request.method == "POST" and not _csrf_ok():
                abort(403)
            return view(*args, **kwargs)  # type: ignore[no-any-return]

        return wrapped  # type: ignore[return-value]

    return decorator
