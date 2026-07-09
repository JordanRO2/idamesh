"""IDA-free unit tests for the static ``ida://`` resources.

Drives the four zero-argument static resources — ``ida://functions``,
``ida://globals``, ``ida://imports`` and ``ida://strings`` — end-to-end through
the MCP engine with fake use-cases and an inline executor (no IDA, no transport).
Each test asserts the resource lists and that ``resources/read`` returns
``application/json`` contents whose decoded ``text`` is exactly the equivalent
listing tool's view of the first page — i.e. the reused view converter's output.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, List, TypeVar

import pytest

from idamesh.application.dto.functions import ListFuncsCommand, ListFuncsResult
from idamesh.application.dto.globals import ListGlobalsCommand, ListGlobalsResult
from idamesh.application.dto.imports import ListImportsCommand, ListImportsResult
from idamesh.application.dto.list_strings import (
    ListStringsCommand,
    ListStringsResult,
)
from idamesh.domain.entities.data import Global
from idamesh.domain.entities.function import Function
from idamesh.domain.entities.imports import Import
from idamesh.domain.entities.string_item import StringItem
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import Page
from idamesh.interface.catalog.imports import list_imports_view
from idamesh.interface.catalog.list_strings import list_strings_view
from idamesh.interface.catalog.resources.static import (
    FUNCTIONS_URI,
    GLOBALS_URI,
    IMPORTS_URI,
    STRINGS_URI,
    register_static_resources,
)
from idamesh.interface.catalog.views import list_funcs_view, list_globals_view
from idamesh.interface.mcp.engine import McpEngine
from idamesh.interface.mcp.registry import Registry
from tests.mcp.support import FakeCtx

T = TypeVar("T")


class _InlineExecutor:
    """A no-marshal ``MainThreadExecutor``: runs the job on the calling thread."""

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        return job()

    def on_kernel_thread(self) -> bool:
        return True


@dataclass
class _FakeListUseCase:
    """A canned ``execute``: records each command and returns a fixed result."""

    result: Any
    seen: List[Any] = field(default_factory=list)

    def execute(self, command: Any) -> Any:
        self.seen.append(command)
        return self.result


# -- canned first pages (real domain entities → real view projections) -------

_FUNCS_PAGE: Page[Function] = Page(
    items=[
        Function(
            ea=Address(0x401000),
            name="main",
            size=0x40,
            end_ea=Address(0x401040),
            is_library=False,
            is_thunk=False,
        ),
        Function(ea=Address(0x401100), name="thunk_recv", size=0x6, is_thunk=True),
    ],
    offset=0,
    count=2,
    total=2,
    truncated=False,
)

_GLOBALS_PAGE: Page[Global] = Page(
    items=[Global(ea=Address(0x402000), name="g_flag", size=4, type_name="int")],
    offset=0,
    count=1,
    total=1,
    truncated=False,
)

_IMPORTS_PAGE: Page[Import] = Page(
    items=[
        Import(
            ea=Address(0x403000),
            name="CreateFileW",
            module="kernel32.dll",
            ordinal=None,
        )
    ],
    offset=0,
    count=1,
    total=1,
    truncated=False,
)

_STRINGS_PAGE: Page[StringItem] = Page(
    items=[StringItem(address=Address(0x404000), length=5, kind="C", value="hello")],
    offset=0,
    count=1,
    total=1,
    truncated=False,
)


def _build_engine() -> tuple[McpEngine, dict[str, _FakeListUseCase]]:
    """Wire the four static resources with fakes onto a ready engine."""
    reg = Registry()
    fakes = {
        "functions": _FakeListUseCase(ListFuncsResult(page=_FUNCS_PAGE)),
        "globals": _FakeListUseCase(ListGlobalsResult(page=_GLOBALS_PAGE)),
        "imports": _FakeListUseCase(ListImportsResult(page=_IMPORTS_PAGE)),
        "strings": _FakeListUseCase(ListStringsResult(page=_STRINGS_PAGE)),
    }
    register_static_resources(
        reg,
        list_funcs_use_case=fakes["functions"],
        list_globals_use_case=fakes["globals"],
        list_imports_use_case=fakes["imports"],
        list_strings_use_case=fakes["strings"],
        executor=_InlineExecutor(),
    )
    engine = McpEngine(reg)
    engine.initialized(None, FakeCtx())
    return engine, fakes


# -- listing ------------------------------------------------------------------


def test_static_resources_are_all_listed_as_literal_resources() -> None:
    engine, _ = _build_engine()

    listing = engine.resources_list(None, FakeCtx())

    by_uri = {row["uri"]: row for row in listing["resources"]}
    assert set(by_uri) == {FUNCTIONS_URI, GLOBALS_URI, IMPORTS_URI, STRINGS_URI}
    for uri, name in (
        (FUNCTIONS_URI, "functions"),
        (GLOBALS_URI, "globals"),
        (IMPORTS_URI, "imports"),
        (STRINGS_URI, "strings"),
    ):
        assert by_uri[uri]["name"] == name
        assert by_uri[uri]["mimeType"] == "application/json"
        # Every static resource carries an authored, non-empty description.
        assert by_uri[uri]["description"]


def test_static_resources_are_not_templates() -> None:
    engine, _ = _build_engine()

    templates = engine.resources_templates_list(None, FakeCtx())

    assert templates["resourceTemplates"] == []


# -- read: contents shape mirrors the equivalent tool's view ------------------


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        (FUNCTIONS_URI, list_funcs_view(_FUNCS_PAGE)),
        (GLOBALS_URI, list_globals_view(_GLOBALS_PAGE)),
        (IMPORTS_URI, list_imports_view(_IMPORTS_PAGE)),
        (STRINGS_URI, list_strings_view(_STRINGS_PAGE)),
    ],
)
def test_static_resource_read_returns_json_contents(
    uri: str, expected: dict
) -> None:
    engine, _ = _build_engine()

    read = engine.resources_read({"uri": uri}, FakeCtx())

    contents = read["contents"]
    assert len(contents) == 1
    entry = contents[0]
    assert entry["uri"] == uri
    assert entry["mimeType"] == "application/json"
    assert json.loads(entry["text"]) == expected


def test_functions_resource_payload_projects_rows() -> None:
    engine, _ = _build_engine()

    read = engine.resources_read({"uri": FUNCTIONS_URI}, FakeCtx())
    payload = json.loads(read["contents"][0]["text"])

    assert payload["offset"] == 0
    assert payload["total"] == 2
    assert payload["truncated"] is False
    assert [row["name"] for row in payload["items"]] == ["main", "thunk_recv"]
    assert payload["items"][0]["start"] == "0x401000"
    assert payload["items"][1]["is_thunk"] is True


def test_imports_resource_payload_projects_rows() -> None:
    engine, _ = _build_engine()

    read = engine.resources_read({"uri": IMPORTS_URI}, FakeCtx())
    payload = json.loads(read["contents"][0]["text"])

    assert payload["items"][0] == {
        "name": "CreateFileW",
        "address": "0x403000",
        "module": "kernel32.dll",
        "ordinal": None,
    }


def test_strings_resource_payload_projects_rows() -> None:
    engine, _ = _build_engine()

    read = engine.resources_read({"uri": STRINGS_URI}, FakeCtx())
    payload = json.loads(read["contents"][0]["text"])

    assert payload["items"][0] == {
        "address": "0x404000",
        "length": 5,
        "type": "C",
        "value": "hello",
    }


# -- read: each resource requests the first page (use-case defaults) ----------


@pytest.mark.parametrize(
    ("uri", "key", "command_type"),
    [
        (FUNCTIONS_URI, "functions", ListFuncsCommand),
        (GLOBALS_URI, "globals", ListGlobalsCommand),
        (IMPORTS_URI, "imports", ListImportsCommand),
        (STRINGS_URI, "strings", ListStringsCommand),
    ],
)
def test_static_resource_reads_the_first_page(
    uri: str, key: str, command_type: type
) -> None:
    engine, fakes = _build_engine()

    engine.resources_read({"uri": uri}, FakeCtx())

    seen = fakes[key].seen
    assert len(seen) == 1
    command = seen[0]
    assert isinstance(command, command_type)
    # The first page: the use-case defaults (offset 0, count 100).
    assert command.offset == 0
    assert command.count == 100
