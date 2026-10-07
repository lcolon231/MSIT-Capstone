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
    context, users = run.build_context()
    assert len(context.approvals.list_pending()) == 1
    assert users.verify("operator", "operator-pass") is not None
    # The demo history writer and the monitor's writer share one log: the chain must not fork.
    context.sessions.open_session()  # an append through the MONITOR's writer
    result = verify_chain(audit)
    assert result.ok, result.reason
    assert result.records == 3
