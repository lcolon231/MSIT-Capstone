"""The console demo launcher (src/web/run.py) sits on a real composed monitor."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.audit.chain import verify_chain
from src.web import run


def test_build_context_seeds_one_pending_approval_and_keeps_audit_chain_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = Path(__file__).resolve().parents[2]
    audit = tmp_path / "demo.jsonl"
    monkeypatch.setenv("MONITOR_POLICY", str(repo / "policies" / "rmm.yaml"))
    monkeypatch.setenv("MONITOR_AUDIT", str(audit))
    monkeypatch.setenv("OP_PASS", "s3cret")
    monkeypatch.delenv("VIEW_PASS", raising=False)
    context, users = run.build_context()
    assert len(context.approvals.list_pending()) == 1
    assert users.verify("operator", "s3cret") is not None
    # The demo history writer and the monitor's writer share one log: the chain must not fork.
    context.sessions.open_session()  # an append through the MONITOR's writer
    result = verify_chain(audit)
    assert result.ok, result.reason
    assert result.records == 3


def test_build_context_without_op_pass_exits_before_writing_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit = tmp_path / "demo.jsonl"
    monkeypatch.setenv("MONITOR_AUDIT", str(audit))
    monkeypatch.delenv("OP_PASS", raising=False)
    with pytest.raises(SystemExit):
        run.build_context()
    assert not audit.exists()


@pytest.mark.parametrize(
    ("username", "password"), [("operator", "operator-pass"), ("viewer", "viewer-pass")]
)
def test_former_default_credentials_are_not_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, username: str, password: str
) -> None:
    repo = Path(__file__).resolve().parents[2]
    monkeypatch.setenv("MONITOR_POLICY", str(repo / "policies" / "rmm.yaml"))
    monkeypatch.setenv("MONITOR_AUDIT", str(tmp_path / "demo.jsonl"))
    monkeypatch.setenv("OP_PASS", "s3cret")
    monkeypatch.delenv("VIEW_PASS", raising=False)
    _, users = run.build_context()
    assert users.verify(username, password) is None


def test_main_serves_the_console_on_host_and_port_from_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import flask

    repo = Path(__file__).resolve().parents[2]
    seen: dict[str, object] = {}
    monkeypatch.setattr(flask.Flask, "run", lambda app, host, port: seen.update(host=host, port=port))
    monkeypatch.setenv("MONITOR_POLICY", str(repo / "policies" / "rmm.yaml"))
    monkeypatch.setenv("MONITOR_AUDIT", str(tmp_path / "demo.jsonl"))
    monkeypatch.setenv("OP_PASS", "s3cret")
    monkeypatch.setenv("HOST", "127.0.0.2")
    monkeypatch.setenv("PORT", "5099")
    run.main()
    assert seen == {"host": "127.0.0.2", "port": 5099}
