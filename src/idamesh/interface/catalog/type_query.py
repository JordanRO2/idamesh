"""Catalog registration and wire-shape projection for ``type_query``.

The ``TypeMatchView`` / ``TypeQueryView`` ``TypedDict``s give the schema compiler
an object-rooted ``outputSchema``; :func:`type_query_view` renders each matched
type into that flat shape (only ``name`` / ``kind`` / ``size`` surfaced — member
detail belongs to ``type_inspect``). The field names mirror the interoperability
contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, TypedDict

from idamesh.application.contexts.types import TypeQueryUseCase
from idamesh.application.dto.types import (
    DEFAULT_TYPE_QUERY_LIMIT,
    TypeQueryCommand,
    TypeQueryResult,
)
from idamesh.domain.entities.type_info import TypeInfo
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class TypeMatchView(TypedDict):
    """One matched type in a ``type_query`` result."""

    name: str
    kind: str
    size: int


class TypeQueryView(TypedDict):
    """The named types whose name matched ``query``."""

    query: str
    matches: List[TypeMatchView]
    truncated: bool


def type_match_view(info: TypeInfo) -> TypeMatchView:
    """Project one matched :class:`TypeInfo` into its wire shape."""
    return TypeMatchView(name=info.name, kind=info.kind, size=info.size)


def type_query_view(result: TypeQueryResult) -> TypeQueryView:
    """Project a ``type_query`` result into its wire shape."""
    return TypeQueryView(
        query=result.query,
        matches=[type_match_view(info) for info in result.matches],
        truncated=result.truncated,
    )


def register_type_query(
    registry: Registry,
    *,
    type_query_use_case: TypeQueryUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``type_query`` against the type-catalog query use-case."""

    @registry.tool(name="type_query")
    def type_query(query: str = "", limit: int = DEFAULT_TYPE_QUERY_LIMIT) -> TypeQueryView:
        """Search the database's local type catalog for named types whose name
        contains ``query`` (case-insensitive); an empty ``query`` lists every
        named type. ``limit`` caps how many matches are returned (clamped to a
        server maximum). The result echoes the ``query`` and lists each match's
        ``name``, its coarse ``kind`` (e.g. struct / union / enum / typedef /
        pointer), and its byte ``size``, with ``truncated`` set when the cap
        elided further matches. Member detail is available through
        ``type_inspect``. Read-only."""
        command = TypeQueryCommand(query=query, limit=limit)
        result = run_use_case(
            executor, lambda: type_query_use_case.execute(command)
        )
        return type_query_view(result)
