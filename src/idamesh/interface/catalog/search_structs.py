"""Catalog registration and wire-shape projection for ``search_structs``.

The ``StructMatchView`` / ``SearchStructsView`` ``TypedDict``s give the schema
compiler an object-rooted ``outputSchema``; :func:`search_structs_view` renders
each matched aggregate into that flat shape (``name`` / ``size`` /
``member_count``). The field names mirror the interoperability contract; the
projection is ours.
"""

from __future__ import annotations

from typing import List, TypedDict

from idamesh.application.contexts.search_structs import SearchStructsUseCase
from idamesh.application.dto.search_structs import (
    DEFAULT_SEARCH_STRUCTS_LIMIT,
    SearchStructsCommand,
    SearchStructsResult,
)
from idamesh.domain.entities.struct_summary import StructSummary
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class StructMatchView(TypedDict):
    """One matched aggregate type in a ``search_structs`` result."""

    name: str
    size: int
    member_count: int


class SearchStructsView(TypedDict):
    """The struct/union types whose name matched ``query``."""

    query: str
    matches: List[StructMatchView]
    truncated: bool


def struct_match_view(summary: StructSummary) -> StructMatchView:
    """Project one matched :class:`StructSummary` into its wire shape."""
    return StructMatchView(
        name=summary.name,
        size=summary.size,
        member_count=summary.member_count,
    )


def search_structs_view(result: SearchStructsResult) -> SearchStructsView:
    """Project a ``search_structs`` result into its wire shape."""
    return SearchStructsView(
        query=result.query,
        matches=[struct_match_view(summary) for summary in result.matches],
        truncated=result.truncated,
    )


def register_search_structs(
    registry: Registry,
    *,
    search_structs_use_case: SearchStructsUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``search_structs`` against the struct-search use-case."""

    @registry.tool(name="search_structs")
    def search_structs(
        query: str = "", limit: int = DEFAULT_SEARCH_STRUCTS_LIMIT
    ) -> SearchStructsView:
        """Search the database's aggregate (struct and union) types for those
        whose name contains ``query`` (case-insensitive); an empty ``query`` lists
        every struct/union. ``limit`` caps how many matches are returned (clamped
        to a server maximum). The result echoes the ``query`` and lists each
        match's ``name``, total byte ``size``, and ``member_count``, with
        ``truncated`` set when the cap elided further matches. Field-level layout
        is available through ``read_struct`` and ``type_inspect``. Read-only."""
        command = SearchStructsCommand(query=query, limit=limit)
        result = run_use_case(
            executor, lambda: search_structs_use_case.execute(command)
        )
        return search_structs_view(result)
