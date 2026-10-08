"""Model adapter parsing behavior."""

import io
import json
import urllib.error

import pytest

from src.agent import model as model_mod
from src.agent.model import ModelError, OllamaModel
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


# --- response parsing -------------------------------------------------------------------------


def test_parse_final_answer() -> None:
    response = OllamaModel._parse('{"final": "all done"}')
    assert (response.proposal, response.final_text) == (None, "all done")


@pytest.mark.parametrize("content", ["not json", '{"neither": 1}', "[1, 2]"])
def test_parse_rejects_content_that_is_not_a_step(content: str) -> None:
    with pytest.raises(ModelError):
        OllamaModel._parse(content)


# --- HTTP layer (urlopen faked; no Ollama needed) --------------------------------------------


class _FakeResponse(io.BytesIO):
    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _serve(monkeypatch: pytest.MonkeyPatch, outcome: object) -> list:
    requests: list = []

    def fake_urlopen(request, timeout: float):  # type: ignore[no-untyped-def]
        requests.append((request, timeout))
        if isinstance(outcome, BaseException):
            raise outcome
        return _FakeResponse(outcome)  # type: ignore[arg-type]

    monkeypatch.setattr(model_mod.urllib.request, "urlopen", fake_urlopen)
    return requests


def test_post_sends_json_to_the_configured_host(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _serve(monkeypatch, json.dumps({"message": {"content": '{"final": "ok"}'}}).encode())
    model = OllamaModel(host="http://ollama.test:11434")
    assert model.next_step("t", ()).final_text == "ok"
    (request, timeout) = requests[0]
    assert request.full_url == "http://ollama.test:11434/api/chat"
    assert request.get_method() == "POST"
    assert json.loads(request.data)["format"] == "json"
    assert timeout == 120


@pytest.mark.parametrize(
    "outcome",
    [urllib.error.URLError("refused"), TimeoutError("slow"), b"not json"],
    ids=["unreachable", "timeout", "bad-json"],
)
def test_post_failures_raise_model_error(monkeypatch: pytest.MonkeyPatch, outcome: object) -> None:
    _serve(monkeypatch, outcome)
    with pytest.raises(ModelError, match="Ollama request"):
        OllamaModel()._post("/api/chat", {})


def test_post_rejects_a_non_object_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    _serve(monkeypatch, b"[1, 2]")
    with pytest.raises(ModelError, match="non-object"):
        OllamaModel()._post("/api/chat", {})


# --- prompt rendering ------------------------------------------------------------------------


def test_system_message_lists_the_catalog() -> None:
    model = OllamaModel(catalog=(ToolSpec("list_files", ()), ToolSpec("read_file", ("path",))))
    message = model._system_message()
    assert "list_files (args: no arguments)" in message
    assert "read_file (args: path)" in message
    assert OllamaModel()._system_message() == OllamaModel._SYSTEM


def _denied() -> ToolResult:
    return ToolResult(ResultStatus.DENIED, DecisionSummary(Verdict.DENY, "default", "no rule"))


def test_render_hints_when_a_proposed_name_is_not_in_the_catalog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = OllamaModel(catalog=(ToolSpec("read_file", ("path",)),))
    replies = iter(['{"tool": "cat_file", "args": {}}', '{"tool": "read_file", "args": {}}'])
    monkeypatch.setattr(model, "_post", lambda _p, _b: {"message": {"content": next(replies)}})
    model.next_step("t", ())
    model.next_step("t", (_denied(),))  # non-empty history keeps the first proposal's name
    rendered = model._render("t", (_denied(), _denied()))
    assert "'cat_file' is not an available tool name. Use one of: read_file." in rendered
    assert rendered.count("is not an available tool name") == 1  # the valid name gets no hint


def test_render_shows_executed_output_and_truncates_it() -> None:
    long = {"text": "x" * 1000}
    result = ToolResult(ResultStatus.EXECUTED, DecisionSummary(Verdict.ALLOW, "r", "ok"), long)
    rendered = OllamaModel()._render("t", (result,))
    assert "   output: " in rendered
    assert rendered.rstrip().splitlines()[-3].endswith("... [truncated]")


def test_render_payload_falls_back_to_str_for_unserialisable_output() -> None:
    circular: list = []
    circular.append(circular)
    assert OllamaModel._render_payload(circular) == "[[...]]"
