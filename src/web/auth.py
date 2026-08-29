"""Console authentication and role-based access control (D5 operator surface).

Two roles:
  - ``operator`` — may approve / deny gated calls (the only role that can act);
  - ``viewer``   — read-only: dashboard, audit feed, policy, and sequence inspector.

Passwords are stored only as werkzeug hashes; the plaintext is never retained. Approval intent
still comes exclusively from an authenticated operator POST resolved by approval id — never from
an agent or a call's arguments (see gate.py).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from functools import wraps
from typing import Any, Callable, TypeVar

from flask import abort, redirect, session, url_for
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


def current_role() -> Role | None:
    raw = session.get("role")
    return Role(raw) if raw is not None else None


def login_required(view: F) -> F:
    """Redirect unauthenticated requests to the login page."""

    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> ResponseReturnValue:
        if "user" not in session:
            return redirect(url_for("console.login"))
        return view(*args, **kwargs)  # type: ignore[no-any-return]

    return wrapped  # type: ignore[return-value]


def requires_role(role: Role) -> Callable[[F], F]:
    """Gate a view behind a specific role. Authenticated-but-wrong-role gets 403; anonymous is
    redirected to login."""

    def decorator(view: F) -> F:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> ResponseReturnValue:
            if "user" not in session:
                return redirect(url_for("console.login"))
            if current_role() is not role:
                abort(403)
            return view(*args, **kwargs)  # type: ignore[no-any-return]

        return wrapped  # type: ignore[return-value]

    return decorator
