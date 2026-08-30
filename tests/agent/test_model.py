"""Model adapter parsing behavior."""

import json

import pytest

from src.agent.model import OllamaModel
from src.transport.contract import DecisionSummary, ResultStatus, ToolResult, ToolSpec, Verdict


@pytest.mark.parametrize("raw_args", [["/tmp/scratch.log"], "/tmp/scratch.log"])
def test_non_object_args_normalize_to_empty_mapping(raw_args: object) -> None:
    content = json.dumps({"tool": "read_file", "args": raw_args})

    response = OllamaModel._parse(content)

    assert response.proposal is not None
    assert response.proposal.args == {}


def test_render_corrects_non_object_args_on_next_turn(monkeypatch: pytest.MonkeyPatch) -> None:
    content = '{"tool": "read_file", "args": ["/tmp/scratch.log"]}'
    model = OllamaModel(catalog=(ToolSpec("read_file", ("path",)),))
    monkeypatch.setattr(
        model,
        "_post",
        lambda _path, _payload: {"message": {"content": content}},
    )
    model.next_step("Read the scratch log", ())
    history = (
        ToolResult(
            ResultStatus.DENIED,
            DecisionSummary(Verdict.DENY, "default", "missing path"),
        ),
    )

    rendered = model._render("Read the scratch log", history)

    assert "'args' was not a JSON object and was normalized to {}" in rendered
