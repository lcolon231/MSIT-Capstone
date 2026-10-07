"""Shared web-test helpers (password hashing is made cheap suite-wide in tests/conftest.py)."""

from __future__ import annotations

from flask.testing import FlaskClient


def csrf(client: FlaskClient) -> str:
    """The CSRF token the console issued to this client's session at login."""
    with client.session_transaction() as sess:
        token = sess.get("csrf")
    assert isinstance(token, str) and token, "no CSRF token — is the client logged in?"
    return token


class FakeClock:
    """An injectable clock (seconds) a test advances explicitly — no sleeping."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds
