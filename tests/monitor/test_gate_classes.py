"""Every D5 gate class routes to GATE end-to-end — issue #13 criterion 1.

The four irreversible classes — fund-transfer, file-delete, network-send, credential-access —
each reach the approval gate through the full mediated flow: an un-resolved gate times out to
DENIED (tool never runs) while the decision stays GATE and a class-tagged ApprovalResolutionEvent
is written; an operator approval lets the tool execute.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from src.audit.events import ApprovalResolutionEvent
from src.audit.replay import replay
from src.audit.writer import AuditWriter
from src.monitor.gate import ApprovalQueue
from src.monitor.service import MonitorService
from src.monitor.session import RetentionConfig, SessionRegistry
from src.monitor.types import GateClass
from src.policy.loader import load_policy
from src.tools.banking import BankingState, register_banking
from src.tools.base import ToolRegistry
from src.tools.credentials import CredentialStore, register_credentials
from src.tools.files import FileStore, register_files
from src.tools.network import NetworkLog, register_network
from src.transport.contract import ResultStatus, ToolCallProposal, Verdict

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICIES = REPO_ROOT / "policies"


def propose(tool: str, **args: object) -> ToolCallProposal:
    return ToolCallProposal(tool=tool, args=args)


# (policy file, proposal, expected gate class) — one GATE-class operation per domain.
DOMAINS = [
    ("banking.yaml", propose("transfer_funds", to="acme", amount=100), GateClass.FUND_TRANSFER),
    ("files.yaml", propose("delete_file", path="/etc/data"), GateClass.FILE_DELETE),
    ("network.yaml", propose("send_network", dest="10.0.0.9", payload="x"), GateClass.NETWORK_SEND),
    ("credentials.yaml", propose("access_credential", name="db"), GateClass.CREDENTIAL_ACCESS),
]


def build(tmp_path: Path, policy_file: str, timeout: float):
    registry = ToolRegistry()
    register_banking(registry, BankingState(balances={"acct-1": 1000}, payees={"acct-1": []}))
    register_files(registry, FileStore(files={"acct-1": ["/etc/data"]}))
    register_network(registry, NetworkLog())
    register_credentials(registry, CredentialStore(secrets={"db": "s3cr3t"}))
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditWriter(audit_path)
    sessions = SessionRegistry(audit, RetentionConfig())
    queue = ApprovalQueue()
    service = MonitorService(
        load_policy(POLICIES / policy_file), registry, audit, sessions, queue, approval_timeout_s=timeout
    )
    return service, service.open_session("acct-1"), queue, audit_path


def _resolve_when_pending(queue: ApprovalQueue, approved: bool) -> threading.Thread:
    def run() -> None:
        for _ in range(400):
            pending = queue.list_pending()
            if pending:
                queue.resolve(pending[0].approval_id, approved, "op-1")
                return
            time.sleep(0.005)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


@pytest.mark.parametrize("policy_file,proposal,gate_class", DOMAINS)
def test_gate_class_routes_and_is_audited(tmp_path, policy_file, proposal, gate_class) -> None:
    service, session, _queue, audit_path = build(tmp_path, policy_file, timeout=0.05)
    result = service.handle(proposal, session)
    # Un-resolved -> DENIED, but the decision is GATE (routed to a human, not a per-call DENY).
    assert result.decision.verdict is Verdict.GATE
    assert result.status is ResultStatus.DENIED
    resolutions = [e for e in replay(audit_path) if isinstance(e, ApprovalResolutionEvent)]
    assert len(resolutions) == 1
    assert resolutions[0].gate_class is gate_class
    assert resolutions[0].resolution == "timed_out"


@pytest.mark.parametrize("policy_file,proposal,gate_class", DOMAINS)
def test_gate_class_executes_on_operator_approval(tmp_path, policy_file, proposal, gate_class) -> None:
    service, session, queue, _ = build(tmp_path, policy_file, timeout=2.0)
    approver = _resolve_when_pending(queue, approved=True)
    result = service.handle(proposal, session)
    approver.join(timeout=2.0)
    assert result.status is ResultStatus.EXECUTED
    assert result.decision.verdict is Verdict.GATE  # gated, then operator-approved
