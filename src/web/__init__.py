"""Flask operator console (issue #14, T4.2) — the monitor's read + approve surface.

`create_app` builds the app from a `ConsoleContext` (shared monitor objects) and a `UserStore`
(operator/viewer accounts). The console is a separate presentation layer: it observes the audit
log, live sequence state, and loaded policy, and resolves gated approvals through the shared
queue. It never imports `src.tools` or the verdict engine.
"""

from __future__ import annotations

import secrets
import time
from datetime import timedelta
from typing import Callable

from flask import Flask

from src.web import views
from src.web.auth import (
    DEFAULT_ABSOLUTE_TIMEOUT_S,
    DEFAULT_IDLE_TIMEOUT_S,
    Role,
    UserStore,
    csrf_token,
    users_from_env,
)
from src.web.context import ConsoleContext

__all__ = ["ConsoleContext", "Role", "UserStore", "create_app", "users_from_env"]


def create_app(
    context: ConsoleContext,
    users: UserStore,
    secret_key: str | None = None,
    idle_timeout_s: float = DEFAULT_IDLE_TIMEOUT_S,
    absolute_timeout_s: float = DEFAULT_ABSOLUTE_TIMEOUT_S,
    clock: Callable[[], float] = time.time,
) -> Flask:
    """Construct the console app. `secret_key` signs the session cookie; a random one is used if
    none is supplied (fine for a single-process demo, but set it explicitly in deployment).

    Sessions expire after `idle_timeout_s` without a request or `absolute_timeout_s` after
    login, measured by `clock` (injectable for tests)."""
    app = Flask(__name__)
    app.secret_key = secret_key or secrets.token_hex(32)
    app.config["CONSOLE"] = context
    app.config["USERS"] = users
    app.config["CLOCK"] = clock
    app.config["IDLE_TIMEOUT_S"] = idle_timeout_s
    app.config["ABSOLUTE_TIMEOUT_S"] = absolute_timeout_s
    # Browser-side hardening; the server-side checks in auth.py are what actually enforce expiry
    # and CSRF. SameSite=Lax keeps the cookie off cross-site POSTs as a second CSRF layer.
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=absolute_timeout_s)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.jinja_env.globals["csrf_token"] = csrf_token
    app.register_blueprint(views.bp)
    return app
