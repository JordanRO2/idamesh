"""Catalog registration and wire-shape projection for ``imports_query``.

The ``ImportMatchView`` / ``ImportsQueryView`` ``TypedDict``s give the schema
compiler an object-rooted ``outputSchema``; :func:`imports_query_view` renders each
matched :class:`~idamesh.domain.entities.imports.Import` into that flat shape
(address as ``0x`` hex). The field names mirror the interoperability contract; the
projection is ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.imports_query import ImportsQueryUseCase
from idamesh.application.dto.imports_query import (
    DEFAULT_IMPORTS_QUERY_LIMIT,
    ImportsQueryCommand,
    ImportsQueryResult,
)
from idamesh.domain.entities.imports import Import
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class ImportMatchView(TypedDict):
    """One matched imported symbol in an ``imports_query`` result."""

    name: str
    address: str
    module: str
    ordinal: Optional[int]


class ImportsQueryView(TypedDict):
    """The imported symbols that matched the query."""

    matches: List[ImportMatchView]
    truncated: bool


def import_match_view(item: Import) -> ImportMatchView:
    """Project one :class:`Import` into its wire shape."""
    return ImportMatchView(
        name=item.name,
        address=item.ea.hex(),
        module=item.module,
        ordinal=item.ordinal,
    )


def imports_query_view(result: ImportsQueryResult) -> ImportsQueryView:
    """Project an ``imports_query`` result into its wire shape."""
    return ImportsQueryView(
        matches=[import_match_view(item) for item in result.matches],
        truncated=result.truncated,
    )


def register_imports_query(
    registry: Registry,
    *,
    imports_query_use_case: ImportsQueryUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``imports_query`` against the import-filter use-case."""

    @registry.tool(name="imports_query")
    def imports_query(
        name: str = "",
        module: str = "",
        limit: int = DEFAULT_IMPORTS_QUERY_LIMIT,
    ) -> ImportsQueryView:
        """Filter the module's imported symbols. ``name`` matches a case-insensitive
        substring of the imported symbol name and ``module`` a case-insensitive
        substring of the originating library; either empty leaves that axis
        unfiltered, and the two combine as a conjunction. ``limit`` caps how many
        matches are returned (clamped to a server maximum). Each match carries the
        symbol ``name``, its import-table ``address`` (``0x``-hex), the ``module``
        it is drawn from, and its ``ordinal`` when the platform links by ordinal;
        ``truncated`` is set when the cap elided further matches. Read-only."""
        command = ImportsQueryCommand(name=name, module=module, limit=limit)
        result = run_use_case(
            executor, lambda: imports_query_use_case.execute(command)
        )
        return imports_query_view(result)
