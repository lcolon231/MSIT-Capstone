"""Cryptographic tamper-evidence for the append-only audit log (issue #56, T8.3).

The writer alone being append-only is not enough: nothing about an independently-serialized JSONL
line lets a reader detect that an *earlier* line was edited or deleted after the fact. This module
adds a hash chain. Each written record carries:

  - ``prev_sha256`` — the SHA-256 of the *previous written line* (``GENESIS`` for the first), so any
    edit or deletion of an earlier line breaks the chain from that point forward; and
  - ``seq`` — a monotonic 0-based record counter, so a removed or reordered mid-file line is caught
    directly, not only via the hash.

``verify_chain`` walks the file and reports the first broken link (the tamper location). The chain
is a property of the *log envelope*, not of the semantic event types — the event dataclasses stay
pure value objects (``monitor/types.py`` invariant), and ``from_jsonl`` ignores these envelope keys
so ``replay`` is unaffected.

**Honest limitation.** Forward hash-chaining cannot, from the file alone, detect that the *last*
record was truncated — the remaining prefix is still internally consistent. Detecting end-truncation
requires sealing the head hash (and/or record count) out-of-band. That is a documented residual;
see ``docs/design/residual-risks.md`` and the report's Maintenance/Security/Compliance chapter.

    python -m src.audit.chain results/final.jsonl   # verify; exit non-zero if tampered
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

# 64 hex zeros: the chain seed for the first record. Distinct from any real SHA-256 in practice.
GENESIS = "0" * 64

PREV_KEY = "prev_sha256"
SEQ_KEY = "seq"


def line_sha256(line: str) -> str:
    """SHA-256 (hex) of a single serialized log line, exactly as written (no trailing newline).

    Writer and verifier both operate on the newline-free JSON text in UTF-8 text mode, so the two
    sides compute an identical digest regardless of the platform's line ending."""
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def envelope_line(event_dict: dict[str, object], prev_sha256: str, seq: int) -> str:
    """Serialize one chained record: the event's fields plus the tamper-evidence envelope. The
    event keys come first (so ``type`` stays first, as ``from_jsonl`` expects); ``prev_sha256`` and
    ``seq`` are appended. Pure — the writer hashes the returned text to seed the next record."""
    payload = {**event_dict, PREV_KEY: prev_sha256, SEQ_KEY: seq}
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def _iter_records(path: Path) -> Iterator[str]:
    """Yield each non-blank line, stripped of its trailing newline, in append order."""
    with Path(path).open("r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\r\n")
            if line.strip():
                yield line


def resume(path: Path) -> tuple[str, int]:
    """Recover the chain head for an existing log: the last line's hash and the next ``seq``. A
    fresh log (missing or empty) starts from ``(GENESIS, 0)``. This lets a new writer process
    continue the chain of a file an earlier process wrote."""
    prev, seq = GENESIS, 0
    if not Path(path).exists():
        return prev, seq
    for line in _iter_records(path):
        prev = line_sha256(line)
        seq += 1
    return prev, seq


@dataclass(frozen=True)
class ChainVerification:
    """Result of walking the chain. ``broken_at`` is the 1-based line number of the first record
    whose link fails — the tamper location — or ``None`` when the chain is intact. ``records`` is
    the count of records verified good before any break (or the total, when intact)."""

    ok: bool
    records: int
    broken_at: int | None
    reason: str


def verify_chain(path: Path) -> ChainVerification:
    """Walk the log and report the first broken link. Detects a mid-file edit (the *next* record's
    ``prev_sha256`` stops matching), a removed or reordered line (``seq`` and hash both break), and
    a corrupt/invalid line. Does not detect last-record truncation — see the module note."""
    prev = GENESIS
    rec = 0
    try:
        for line in _iter_records(Path(path)):
            broken = _check_record(line, prev, rec)
            if broken is not None:
                return ChainVerification(ok=False, records=rec, broken_at=rec + 1, reason=broken)
            prev = line_sha256(line)
            rec += 1
    except FileNotFoundError:
        return ChainVerification(ok=False, records=0, broken_at=None, reason=f"audit log not found: {path}")
    return ChainVerification(ok=True, records=rec, broken_at=None, reason=f"chain intact across {rec} record(s)")


def _check_record(line: str, expected_prev: str, expected_seq: int) -> str | None:
    """Return a failure reason for a record at index `expected_seq`, or ``None`` if it links
    cleanly. Reports the human-facing line number (1-based) in the message."""
    lineno = expected_seq + 1
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return f"line {lineno}: not valid JSON"
    if not isinstance(obj, dict):
        return f"line {lineno}: not a JSON object"
    if obj.get(PREV_KEY) != expected_prev:
        return f"line {lineno}: prev_sha256 mismatch - an earlier record was altered or removed"
    if obj.get(SEQ_KEY) != expected_seq:
        return f"line {lineno}: seq expected {expected_seq}, found {obj.get(SEQ_KEY)!r} - record removed or reordered"
    return None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.audit.chain",
        description="Verify the hash chain of an append-only audit log (tamper-evidence, #56).",
    )
    parser.add_argument("log", help="path to the append-only audit JSONL log")
    args = parser.parse_args(argv)

    result = verify_chain(Path(args.log))
    if result.ok:
        print(f"OK: {result.reason}")
        return 0
    where = f" at line {result.broken_at}" if result.broken_at is not None else ""
    print(f"TAMPER DETECTED{where}: {result.reason}  ({result.records} record(s) verified before the break)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
