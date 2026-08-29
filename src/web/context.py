"""ConsoleContext — the read/act handle the web console holds into the running monitor.

The console shares the monitor's live objects in-process (it never reaches a tool or the policy
engine directly): it reads the append-only audit log, the live sequence state, and the loaded
policy, and it resolves gated approvals through the same `ApprovalQueue` the service blocks on.
It has no path to `src.tools` or to `evaluate` — it can only observe and approve/deny.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.monitor.gate import ApprovalQueue
from src.monitor.session import SessionRegistry
from src.policy.schema import Policy


@dataclass(frozen=True)
class ConsoleContext:
    """Everything the console needs from the monitor process, and nothing more."""

    approvals: ApprovalQueue  # pending-approval queue: list + resolve (operator only)
    sessions: SessionRegistry  # live sequence state, via sessions.live_state()
    policy: Policy  # the loaded, validated policy — for the read-only viewer
    audit_path: Path  # append-only JSONL log — the decision feed / audit view
    policy_source: str = ""  # raw YAML text, shown verbatim in the policy viewer
