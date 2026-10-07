"""Files mock domain (issue #16) — in-process per-principal store, no real filesystem.

Identity comes from the monitor-passed `principal`, never from args; one client can never read
or delete another client's files; reads are side-effect free.
"""

from __future__ import annotations

import pytest

from src.tools.base import ToolRegistry
from src.tools.files import DeleteFile, FileStore, ListFiles, ReadFile, register_files


def store() -> FileStore:
    return FileStore(files={"c1": {"/b": "B", "/a": "A"}, "c2": {"/secret": "S"}})


def test_list_files_returns_sorted_paths_for_principal() -> None:
    assert ListFiles(store()).execute({}, "c1") == {"paths": ["/a", "/b"]}


def test_list_files_unknown_principal_is_empty_and_creates_nothing() -> None:
    s = store()
    assert ListFiles(s).execute({}, "nobody") == {"paths": []}
    assert "nobody" not in s.files


def test_read_file_present_returns_content() -> None:
    assert ReadFile(store()).execute({"path": "/a"}, "c1") == {
        "path": "/a",
        "present": True,
        "content": "A",
    }


def test_read_file_other_principals_file_is_not_visible() -> None:
    result = ReadFile(store()).execute({"path": "/secret"}, "c1")
    assert result["present"] is False
    assert result["content"] is None


def test_read_file_principal_in_args_is_ignored() -> None:
    result = ReadFile(store()).execute({"path": "/secret", "principal": "c2"}, "c1")
    assert result["present"] is False


@pytest.mark.parametrize("path", [None, 42, ["/a"]])
def test_read_file_non_string_path_is_coerced_and_not_found(path: object) -> None:
    assert ReadFile(store()).execute({"path": path}, "c1")["present"] is False


def test_read_file_missing_path_arg_is_not_found() -> None:
    assert ReadFile(store()).execute({}, "c1") == {"path": "", "present": False, "content": None}


def test_read_file_does_not_mutate_store() -> None:
    s = store()
    before = {k: dict(v) for k, v in s.files.items()}
    ReadFile(s).execute({"path": "/a"}, "c1")
    assert s.files == before


def test_delete_file_existing_removes_it() -> None:
    s = store()
    assert DeleteFile(s).execute({"path": "/a"}, "c1") == {"deleted": "/a", "existed": True}
    assert "/a" not in s.files["c1"]


def test_delete_file_missing_reports_not_existed() -> None:
    assert DeleteFile(store()).execute({"path": "/nope"}, "c1")["existed"] is False


def test_delete_file_cannot_touch_another_principals_file() -> None:
    s = store()
    DeleteFile(s).execute({"path": "/secret"}, "c1")
    assert s.files["c2"] == {"/secret": "S"}


def test_register_files_registers_the_three_tools() -> None:
    registry = ToolRegistry()
    register_files(registry, FileStore())
    assert [spec.name for spec in registry.specs()] == ["delete_file", "list_files", "read_file"]
