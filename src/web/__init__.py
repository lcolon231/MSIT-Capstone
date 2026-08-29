"""Flask operator console (issue #14, T4.2) — the monitor's read + approve surface.

`create_app` builds the app from a `ConsoleContext` (shared monitor objects) and a `UserStore`
(operator/viewer accounts). The console is a separate presentation layer: it observes the audit
log, live sequence state, and loaded policy, and resolves gated approvals through the shared
queue. It never imports `src.tools` or the verdict engine.
"""

from __future__ import annotations

import secrets

from flask import Flask

from src.web import views
from src.web.auth import Role, UserStore
from src.web.context import ConsoleContext

__all__ = ["ConsoleContext", "Role", "UserStore", "create_app"]


def create_app(
    context: ConsoleContext,
    users: UserStore,
    secret_key: str | None = None,
) -> Flask:
    """Construct the console app. `secret_key` signs the session cookie; a random one is used if
    none is supplied (fine for a single-process demo, but set it explicitly in deployment)."""
    app = Flask(__name__)
    app.secret_key = secret_key or secrets.token_hex(32)
    app.config["CONSOLE"] = context
    app.config["USERS"] = users
    app.register_blueprint(views.bp)
    return app
