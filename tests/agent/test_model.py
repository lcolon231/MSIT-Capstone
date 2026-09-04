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


def _capture_payload(model: OllamaModel, monkeypatch: pytest.MonkeyPatch) -> dict:
    captured: dict = {}

    def fake_post(_path: str, payload: dict) -> dict:
        captured.update(payload)
        return {"message": {"content": '{"final": "done"}'}}

    monkeypatch.setattr(model, "_post", fake_post)
    model.next_step("do it", ())
    return captured


def test_seed_is_passed_to_ollama_as_a_sampling_option(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = _capture_payload(OllamaModel(seed=7), monkeypatch)
    assert payload["options"]["seed"] == 7


def test_no_seed_sends_no_options_block(monkeypatch: pytest.MonkeyPatch) -> None:
    # Preserve the prior wire format exactly when no seed is requested.
    payload = _capture_payload(OllamaModel(), monkeypatch)
    assert "options" not in payload


def test_temperature_is_passed_to_ollama_as_a_sampling_option(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _capture_payload(OllamaModel(temperature=0.8), monkeypatch)
    assert payload["options"]["temperature"] == 0.8


def test_seed_and_temperature_share_one_options_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A multi-seed variance run needs both: the seed makes one sample reproducible, the
    # temperature is what makes distinct seeds distinct samples at all.
    payload = _capture_payload(OllamaModel(seed=7, temperature=0.8), monkeypatch)
    assert payload["options"] == {"seed": 7, "temperature": 0.8}


def test_no_temperature_sends_no_temperature_option(monkeypatch: pytest.MonkeyPatch) -> None:
    # Default stays exactly as before: seed alone still sends a seed-only options block.
    payload = _capture_payload(OllamaModel(seed=7), monkeypatch)
    assert payload["options"] == {"seed": 7}
