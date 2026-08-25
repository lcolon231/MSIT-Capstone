"""Tamper-resistance evidence (D11): `src/agent` has NO import path to `src/tools`,
`src/policy`, or `src/monitor`.

This is a REAL, runnable test — the deliverable that backs the tamper-resistance claim, not a
stub (see the agent prompt and docs/design/architecture.md §4). It analyzes source statically
(AST), so it works against the Phase 2 interface skeleton without importing or executing it.

Method:
  1. Enumerate every `src/**/*.py` and map it to its dotted module name.
  2. Parse each file's AST and record which first-party `src.*` modules it imports.
  3. Compute the transitive import closure starting from every `src.agent.*` module.
  4. Assert the closure contains no module under the forbidden packages.

If this fails, the agent has gained a path to the tools or the policy and the independence
claim is broken. Fix the imports, not this test.
"""

from __future__ import annotations

import ast
from pathlib import Path

# Repo root = two levels up from this file (tests/ -> repo).
REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"

FORBIDDEN_PREFIXES = ("src.tools", "src.policy", "src.monitor")
AGENT_PREFIX = "src.agent"


def _module_name(path: Path) -> str:
    """Map a file path to its dotted module name relative to the repo root.

    ``src/agent/loop.py`` -> ``src.agent.loop``; ``src/agent/__init__.py`` -> ``src.agent``.
    """
    rel = path.relative_to(REPO_ROOT).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _all_src_modules() -> dict[str, Path]:
    """Every first-party module under ``src/``, keyed by dotted name."""
    return {_module_name(p): p for p in SRC_ROOT.rglob("*.py")}


def _imports_of(path: Path, known: set[str]) -> set[str]:
    """First-party ``src.*`` modules imported by the file at `path`.

    Handles both ``import a.b.c`` and ``from a.b import c``. For ``from a.b import c`` we
    consider both ``a.b`` and ``a.b.c`` as candidates and keep whichever is a real module.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in known:
                    found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0 or node.module is None:  # ignore relative / __future__
                continue
            base = node.module
            if base in known:
                found.add(base)
            for alias in node.names:
                candidate = f"{base}.{alias.name}"
                if candidate in known:
                    found.add(candidate)
    return {m for m in found if m.startswith("src.")}


def _build_graph() -> dict[str, set[str]]:
    modules = _all_src_modules()
    known = set(modules)
    return {name: _imports_of(path, known) for name, path in modules.items()}


def _closure(seeds: set[str], graph: dict[str, set[str]]) -> set[str]:
    seen: set[str] = set()
    stack = list(seeds)
    while stack:
        node = stack.pop()
        for dep in graph.get(node, set()):
            if dep not in seen:
                seen.add(dep)
                stack.append(dep)
    return seen


def test_agent_has_no_path_to_tools_policy_or_monitor() -> None:
    graph = _build_graph()
    agent_modules = {m for m in graph if m == AGENT_PREFIX or m.startswith(AGENT_PREFIX + ".")}
    assert agent_modules, "no src.agent modules found — check the layout"

    reachable = _closure(agent_modules, graph)
    violations = sorted(m for m in reachable if m.startswith(FORBIDDEN_PREFIXES))
    assert not violations, (
        "src/agent gained an import path to forbidden packages: "
        f"{violations}. The agent must reach tools/policy/monitor only across the transport "
        "boundary (D11). Fix the imports."
    )


def test_agent_imports_only_transport_contract_and_client() -> None:
    """Stronger, intent-revealing check: the agent's DIRECT first-party imports are limited to
    the transport contract and client. Tightens the boundary beyond the minimum above."""
    modules = _all_src_modules()
    known = set(modules)
    allowed = {"src.transport", "src.transport.contract", "src.transport.client"}
    for name, path in modules.items():
        if not (name == AGENT_PREFIX or name.startswith(AGENT_PREFIX + ".")):
            continue
        direct = _imports_of(path, known)
        extra = {m for m in direct if not (m in allowed or m.startswith("src.agent"))}
        assert not extra, f"{name} imports disallowed first-party modules: {sorted(extra)}"
