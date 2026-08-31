"""Cryptographic tamper-evidence of the audit log (issue #56, T8.3).

Each written line is chained to the previous one by `prev_sha256` (genesis for the first) plus a
monotonic `seq`, so any edit or deletion of an earlier line breaks the chain from that point on
and a verifier can name the first broken link. Arguments stay hashed; the append-only write path
is unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.audit.chain import GENESIS, ChainVerification, line_sha256, verify_chain
from src.audit.replay import replay
from src.audit.writer import AuditWriter
from tests.audit.samples import decision_ev, lifecycle_ev


def _write(path: Path, n: int, writer: AuditWriter | None = None) -> AuditWriter:
    writer = writer or AuditWriter(path)
    for i in range(n):
        writer.append(decision_ev(call_id=f"c{i}", timestamp=float(i)))
    return writer


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


# --- envelope shape -------------------------------------------------------------------------


def test_writer_emits_prev_hash_and_seq(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write(path, 3)
    objs = [json.loads(line) for line in _lines(path)]

    assert objs[0]["prev_sha256"] == GENESIS  # first record chains to genesis
    assert [o["seq"] for o in objs] == [0, 1, 2]
    # each record's prev_sha256 is the hash of the previous written line
    assert objs[1]["prev_sha256"] == line_sha256(_lines(path)[0])
    assert objs[2]["prev_sha256"] == line_sha256(_lines(path)[1])


def test_args_remain_hashed_never_plaintext(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditWriter(path).append(decision_ev())
    text = path.read_text(encoding="utf-8")
    assert "prev_sha256" in text
    assert "SECRET-IBAN-123" not in text  # sample args are hashed, never stored


# --- verification ---------------------------------------------------------------------------


def test_verify_chain_accepts_untampered_log(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write(path, 4)
    result = verify_chain(path)
    assert result == ChainVerification(ok=True, records=4, broken_at=None, reason=result.reason)
    assert result.broken_at is None


def test_verify_chain_detects_midfile_edit(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write(path, 4)
    lines = _lines(path)
    obj = json.loads(lines[1])
    obj["reason"] = "TAMPERED"  # valid JSON, but the line's bytes change
    lines[1] = json.dumps(obj, ensure_ascii=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_chain(path)
    assert not result.ok
    assert result.broken_at == 3  # the record whose prev_sha256 no longer matches


def test_verify_chain_detects_deleted_line(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write(path, 4)
    lines = _lines(path)
    del lines[1]  # remove a mid-file record
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_chain(path)
    assert not result.ok
    assert result.broken_at == 2


def test_verify_chain_detects_first_line_edit(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write(path, 3)
    lines = _lines(path)
    obj = json.loads(lines[0])
    obj["reason"] = "TAMPERED"
    lines[0] = json.dumps(obj, ensure_ascii=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_chain(path)
    assert not result.ok
    assert result.broken_at == 2


def test_verify_chain_reports_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write(path, 3)
    lines = _lines(path)
    lines[1] = "{ not json"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_chain(path)
    assert not result.ok
    assert result.broken_at == 2


def test_verify_chain_does_not_detect_last_line_truncation(tmp_path: Path) -> None:
    # Honest boundary: forward hash-chaining cannot, from the file alone, detect that the LAST
    # record was dropped — the remaining prefix is still internally consistent. Sealing the head
    # hash out-of-band is the mitigation; documented as a residual limitation.
    path = tmp_path / "audit.jsonl"
    _write(path, 3)
    lines = _lines(path)
    del lines[-1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_chain(path)
    assert result.ok
    assert result.records == 2


def test_verify_chain_reports_missing_file(tmp_path: Path) -> None:
    result = verify_chain(tmp_path / "nope.jsonl")
    assert not result.ok


# --- integration with the rest of the audit layer -------------------------------------------


def test_chain_resumes_across_writer_instances(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write(path, 2)  # first process/instance
    _write(path, 1, writer=AuditWriter(path))  # a fresh instance re-opens and continues

    result = verify_chain(path)
    assert result.ok and result.records == 3
    assert [json.loads(line)["seq"] for line in _lines(path)] == [0, 1, 2]


def test_replay_reads_chained_log_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    events = [decision_ev(call_id="a", timestamp=0.0), lifecycle_ev(),
              decision_ev(call_id="b", timestamp=2.0)]
    writer = AuditWriter(path)
    for event in events:
        writer.append(event)
    # the envelope keys are invisible to replay — it still reconstructs the exact events
    assert list(replay(path)) == events
