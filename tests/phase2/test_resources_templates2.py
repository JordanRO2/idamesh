"""Unit tests for the ``ida://struct/{name}`` template resource.

These drive the real :func:`register_struct_resources` registrar and the real
:class:`~idamesh.interface.mcp.engine.McpEngine` — through ``resources/read`` —
but stand in a fake ``TypeInspectUseCase`` and an inline executor so no IDA (and
no database) is required. Two behaviours are pinned:

* the template lists under ``resources/templates/list`` and a happy-path read
  returns the ``type_inspect`` wire projection wrapped as JSON ``contents``; and
* an unknown type name (the use-case raising ``ValueError``) is mapped to a
  ``resources/read`` resource-not-found protocol error, never a tool ``isError``.
"""

from __future__ import annotations

import json
from typing import Callable, TypeVar

import pytest

from idamesh.application.dto.types import TypeInspectCommand, TypeInspectResult
from idamesh.domain.entities.type_info import TypeInfo, TypeMember
from idamesh.interface.catalog.resources.structs import (
    STRUCT_URI_TEMPLATE,
    register_struct_resources,
)
from idamesh.interface.mcp.engine import ErrorCode, McpEngine, McpError
from idamesh.interface.mcp.registry import Registry
from tests.mcp.support import FakeCtx

T = TypeVar("T")


class _InlineExecutor:
    """A :class:`MainThreadExecutor` that runs the job inline (no marshalling)."""

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        return job()

    def on_kernel_thread(self) -> bool:
        return True


class _FakeTypeInspectUseCase:
    """A stand-in ``TypeInspectUseCase`` over a fixed name -> :class:`TypeInfo` map.

    :meth:`execute` mirrors the real use-case's contract: it resolves the command
    ``name`` and raises ``ValueError`` when no type binds to it — the failure the
    interface layer turns into a resource-not-found. Every call is recorded so a
    test can assert the exact ``name`` the handler forwarded.
    """

    def __init__(self, catalog: dict[str, TypeInfo]) -> None:
        self._catalog = catalog
        self.calls: list[str] = []

    def execute(self, command: TypeInspectCommand) -> TypeInspectResult:
        self.calls.append(command.name)
        info = self._catalog.get(command.name)
        if info is None:
            raise ValueError(f"unknown type: {command.name!r}")
        return TypeInspectResult(type_info=info)


_POINT = TypeInfo(
    name="Point",
    kind="struct",
    size=8,
    members=(
        TypeMember(name="x", type_name="int", offset=0, size=4),
        TypeMember(name="y", type_name="int", offset=4, size=4),
    ),
)


def _ready_engine(use_case: _FakeTypeInspectUseCase) -> McpEngine:
    """Build an initialized engine with only the struct resource registered."""
    registry = Registry()
    register_struct_resources(
        registry,
        type_inspect_use_case=use_case,
        executor=_InlineExecutor(),
    )
    engine = McpEngine(registry)
    engine.initialize({"protocolVersion": "2025-11-25"}, FakeCtx())
    engine.initialized(None, FakeCtx())
    return engine


def test_struct_resource_registers_as_template() -> None:
    registry = Registry()
    register_struct_resources(
        registry,
        type_inspect_use_case=_FakeTypeInspectUseCase({}),
        executor=_InlineExecutor(),
    )

    spec = registry.resources()[STRUCT_URI_TEMPLATE]
    assert spec.is_template is True
    assert spec.name == "struct"
    assert spec.mime_type == "application/json"
    # The lone path param is captured as a string segment.
    assert [p.name for p in spec.params] == ["name"]


def test_struct_template_is_listed() -> None:
    engine = _ready_engine(_FakeTypeInspectUseCase({"Point": _POINT}))

    templates = engine.resources_templates_list(None, FakeCtx())["resourceTemplates"]

    entry = next(t for t in templates if t["uriTemplate"] == STRUCT_URI_TEMPLATE)
    assert entry["name"] == "struct"
    assert entry["mimeType"] == "application/json"


def test_read_struct_returns_type_inspect_projection() -> None:
    use_case = _FakeTypeInspectUseCase({"Point": _POINT})
    engine = _ready_engine(use_case)

    read = engine.resources_read({"uri": "ida://struct/Point"}, FakeCtx())

    contents = read["contents"][0]
    assert contents["uri"] == "ida://struct/Point"
    assert contents["mimeType"] == "application/json"
    assert json.loads(contents["text"]) == {
        "name": "Point",
        "kind": "struct",
        "size": 8,
        "members": [
            {"name": "x", "type": "int", "offset": 0, "size": 4},
            {"name": "y", "type": "int", "offset": 4, "size": 4},
        ],
    }
    # The captured path segment reached the command unchanged.
    assert use_case.calls == ["Point"]


def test_read_unknown_struct_is_resource_not_found() -> None:
    use_case = _FakeTypeInspectUseCase({"Point": _POINT})
    engine = _ready_engine(use_case)

    with pytest.raises(McpError) as excinfo:
        engine.resources_read({"uri": "ida://struct/Missing"}, FakeCtx())

    assert excinfo.value.code == ErrorCode.RESOURCE_NOT_FOUND
    assert excinfo.value.data == {"uri": "ida://struct/Missing"}
    # The handler did forward the (unknown) name before the use-case rejected it.
    assert use_case.calls == ["Missing"]
