"""Argument hashing + append-only JSONL writer (issue #9 / T2.6)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.audit.writer import AuditWriter, decision_event, hash_arguments
from src.monitor.types import GateClass
from src.monitor.verdict import default_deny
from src.transport.contract import Verdict
from tests.audit.samples import decision_ev, make_call


def test_hash_arguments_is_stable_and_order_independent() -> None:
    assert hash_arguments({"a": 1, "b": 2}) == hash_arguments({"b": 2, "a": 1})


def test_hash_arguments_changes_with_value() -> None:
    assert hash_arguments({"a": 1}) != hash_arguments({"a": 2})


def test_decision_event_hashes_args_and_never_stores_plaintext() -> None:
    call = make_call(account="SECRET-IBAN-123", amount=9999)
    event = decision_event(call, default_deny())
    assert event.arg_sha256 == hash_arguments(call.args)
    assert "SECRET-IBAN-123" not in event.arg_sha256


def test_decision_event_carries_verdict_and_rule_id() -> None:
    call = make_call()
    from src.monitor.types import Decision

    decision = Decision(Verdict.GATE, "rmm.export_records.gate", "x", GateClass.DATA_EXPORT)
    event = decision_event(call, decision)
    assert event.verdict is Verdict.GATE
    assert event.rule_id == "rmm.export_records.gate"
    assert event.gate_class is GateClass.DATA_EXPORT


def test_writer_appends_without_rewriting(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    writer.append(decision_ev(call_id="a"))
    writer.append(decision_ev(call_id="b"))
    before = path.read_bytes()
    writer.append(decision_ev(call_id="c"))
    after = path.read_bytes()
    # Append-only: previously written bytes are untouched, one line per event.
    assert after.startswith(before)
    assert len(after.decode("utf-8").splitlines()) == 3


def test_writer_creates_parent_directory(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dir" / "audit.jsonl"
    AuditWriter(path).append(decision_ev())
    assert path.exists()


# --- durability (fsync) -------------------------------------------------------------------


@pytest.mark.real_fsync
def test_writer_fsyncs_every_append_when_durable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import src.audit.writer as writer_mod

    synced: list[int] = []
    monkeypatch.setattr(writer_mod, "_fsync", synced.append)
    writer = AuditWriter(tmp_path / "a.jsonl")
    writer.append(decision_ev())
    writer.append(decision_ev())
    assert len(synced) == 2 and all(isinstance(fd, int) for fd in synced)


@pytest.mark.real_fsync
def test_writer_default_fsync_is_the_real_os_fsync() -> None:
    import os

    import src.audit.writer as writer_mod

    assert writer_mod._fsync is os.fsync


@pytest.mark.real_fsync
def test_writer_not_durable_skips_fsync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import src.audit.writer as writer_mod

    synced: list[int] = []
    monkeypatch.setattr(writer_mod, "_fsync", synced.append)
    AuditWriter(tmp_path / "a.jsonl", durable=False).append(decision_ev())
    assert synced == []


def test_writer_exposes_its_log_path(tmp_path: Path) -> None:
    assert AuditWriter(tmp_path / "a.jsonl").path == tmp_path / "a.jsonl"


def test_operator_digest_is_stable_and_not_plaintext() -> None:
    from src.audit.writer import operator_digest

    assert operator_digest("op") == operator_digest("op") != operator_digest("op2")
    assert "op" not in operator_digest("op")
    assert len(operator_digest("op")) == 64
