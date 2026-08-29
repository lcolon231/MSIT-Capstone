"""Every D5 gate class routes to GATE end-to-end — issue #13 criterion 1.

The four irreversible classes — data-export, file-delete, network-send, credential-access —
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
from src.tools.base import ToolRegistry
from src.tools.credentials import CredentialStore, register_credentials
from src.tools.files import FileStore, register_files
from src.tools.network import NetworkLog, register_network
from src.tools.rmm import EndpointState, register_rmm
from src.transport.contract import ResultStatus, ToolCallProposal, Verdict

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICIES = REPO_ROOT / "policies"


def propose(tool: str, **args: object) -> ToolCallProposal:
    return ToolCallProposal(tool=tool, args=args)


# (policy file, proposal, expected gate class) — one GATE-class operation per domain.
DOMAINS = [
    ("rmm.yaml", propose("export_records", to="acme", count=100), GateClass.DATA_EXPORT),
    ("files.yaml", propose("delete_file", path="/etc/data"), GateClass.FILE_DELETE),
    ("network.yaml", propose("send_network", dest="10.0.0.9", payload="x"), GateClass.NETWORK_SEND),
    ("credentials.yaml", propose("access_credential", name="db"), GateClass.CREDENTIAL_ACCESS),
]


def build(tmp_path: Path, policy_file: str, timeout: float):
    registry = ToolRegistry()
    register_rmm(registry, EndpointState(endpoints={"client-1": ["ep-1"]}, shares={"client-1": ["records"]}, destinations={"client-1": []}))
    register_files(registry, FileStore(files={"client-1": {"/etc/data": "secret"}}))
    register_network(registry, NetworkLog())
    register_credentials(registry, CredentialStore(secrets={"db": "s3cr3t"}))
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditWriter(audit_path)
    sessions = SessionRegistry(audit, RetentionConfig())
    queue = ApprovalQueue()
    service = MonitorService(
        load_policy(POLICIES / policy_file), registry, audit, sessions, queue, approval_timeout_s=timeout
    )
    return service, service.open_session("client-1"), queue, audit_path


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


# Each expanded domain also has a benign, ALLOWed operation the agent can run without a gate.
ALLOW_OPS = [
    ("files.yaml", propose("list_files"), "files.list_files.allow"),
    ("network.yaml", propose("fetch_url", url="http://mock/data"), "network.fetch_url.allow"),
    ("credentials.yaml", propose("list_credentials"), "credentials.list_credentials.allow"),
]


@pytest.mark.parametrize("policy_file,proposal,rule_id", ALLOW_OPS)
def test_benign_domain_op_executes(tmp_path, policy_file, proposal, rule_id) -> None:
    service, session, _queue, _audit = build(tmp_path, policy_file, timeout=0.05)
    result = service.handle(proposal, session)
    assert result.status is ResultStatus.EXECUTED
    assert result.decision.verdict is Verdict.ALLOW
    assert result.decision.rule_id == rule_id
