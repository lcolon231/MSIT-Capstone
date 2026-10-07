"""Monitor composition for the RMM demo domain — a neutral, agent-free builder.

Factored out of ``src/launcher.py`` so BOTH the in-process launcher and the loopback monitor
subprocess (``src/monitor_server.py``) can build the same monitor without either dragging the
other in. This module imports only the enforcement side (`monitor`, `policy`, `tools`, `audit`);
it MUST NOT import `src/agent` — the loopback server runs in the monitor process and importing
the agent there would be meaningless and against the D11 layering.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from src.audit.writer import AuditWriter
from src.monitor.gate import ApprovalQueue
from src.monitor.service import MonitorService
from src.monitor.session import RetentionConfig, SessionRegistry
from src.policy.loader import PolicyError, load_policy
from src.policy.schema import Policy
from src.tools.base import ToolRegistry
from src.tools.rmm import EndpointState, register_rmm

PRINCIPAL = "client-primary"  # the session-bound principal MonitorService assigns by default

_log = logging.getLogger(__name__)


def load_policy_or_deny_all(policy_path: Path) -> Policy:
    """Load the policy, or fall back to `Policy.deny_all()` on any load failure.

    interface-contracts.md §4.5: "The composition root substitutes an immutable deny-all policy
    on any load failure." A monitor that cannot read its policy must still run and DENY every
    call — a crashed monitor leaves callers (e.g. over loopback) with connection errors instead
    of auditable decisions.
    """
    try:
        return load_policy(policy_path)
    except PolicyError as exc:
        # Narrow on purpose: PolicyError is the loader's complete failure contract, so any other
        # exception is a programming error and should surface rather than masquerade as deny-all.
        _log.error("policy load failed; running DENY-ALL (fail-closed): %s", exc)
        return Policy.deny_all()


@dataclass(frozen=True)
class MonitorStack:
    """One composed monitor and the live collaborators it shares with trusted surfaces.

    The operator console must resolve approvals on the SAME queue the service blocks on and read
    the SAME session registry and policy — so the composition root hands these out instead of
    letting a console build look-alike copies that nothing dispatches through."""

    service: MonitorService
    approvals: ApprovalQueue
    sessions: SessionRegistry
    policy: Policy  # what is actually enforced (Policy.deny_all() after a load failure)
    policy_path: Path
    audit_path: Path
    endpoints: EndpointState  # the RMM mock environment (inspection/demo only)


def compose_monitor(
    policy_path: Path,
    audit_path: Path,
    approval_timeout_s: float = 2.0,
    approvals: ApprovalQueue | None = None,
) -> MonitorStack:
    """Compose a monitor over the RMM domain: registry + policy + audit + sessions + gate."""
    endpoints = EndpointState(
        endpoints={PRINCIPAL: ["ep-clinic-01", "ep-clinic-02"]},
        shares={PRINCIPAL: ["patient-records", "billing"]},
        destinations={PRINCIPAL: ["approved-baa-backup"]},
    )
    registry = ToolRegistry()
    register_rmm(registry, endpoints)
    audit = AuditWriter(audit_path)
    sessions = SessionRegistry(audit, RetentionConfig())
    queue = approvals if approvals is not None else ApprovalQueue()
    policy = load_policy_or_deny_all(policy_path)
    service = MonitorService(
        policy, registry, audit, sessions, queue, approval_timeout_s=approval_timeout_s
    )
    return MonitorStack(
        service=service,
        approvals=queue,
        sessions=sessions,
        policy=policy,
        policy_path=Path(policy_path),
        audit_path=Path(audit_path),
        endpoints=endpoints,
    )


def build_monitor(
    policy_path: Path, audit_path: Path, approval_timeout_s: float = 2.0
) -> MonitorService:
    """Just the service — for callers (the in-process launcher) with no console attached."""
    return compose_monitor(policy_path, audit_path, approval_timeout_s).service
