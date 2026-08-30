"""Model adapter parsing behavior."""

import pytest

from src.agent.model import ModelError, OllamaModel


def test_args_shape_error_includes_offending_content() -> None:
    content = '{"tool": "read_file", "args": ["/tmp/scratch.log"]}'

    with pytest.raises(ModelError, match="must be an object") as exc_info:
        OllamaModel._parse(content)

    assert content in str(exc_info.value)
