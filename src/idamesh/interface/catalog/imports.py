"""Catalog registration and wire-shape projection for ``imports``.

The ``ImportView`` / ``ListImportsView`` ``TypedDict``s give the schema compiler
an object-rooted ``outputSchema``; :func:`list_imports_view` renders the domain
page into that flat, JSON-native shape (addresses as ``0x`` hex). The field
*names* mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.imports import ListImportsUseCase
from idamesh.application.dto.imports import ListImportsCommand
from idamesh.domain.entities.imports import Import
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.domain.values.pagination import Page
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class ImportView(TypedDict):
    """One imported-symbol row in an ``imports`` page."""

    name: str
    address: str
    module: str
    ordinal: Optional[int]


class ListImportsView(TypedDict):
    """A page of :class:`ImportView` rows plus continuation metadata."""

    items: List[ImportView]
    offset: int
    count: int
    total: Optional[int]
    truncated: bool
    next_cursor: Optional[str]


def import_view(item: Import) -> ImportView:
    """Project one :class:`Import` into its wire shape."""
    return ImportView(
        name=item.name,
        address=item.ea.hex(),
        module=item.module,
        ordinal=item.ordinal,
    )


def list_imports_view(page: Page[Import]) -> ListImportsView:
    """Project a page of imports into its wire shape."""
    return ListImportsView(
        items=[import_view(item) for item in page.items],
        offset=page.offset,
        count=page.count,
        total=page.total,
        truncated=page.truncated,
        next_cursor=page.next_cursor,
    )


def register_imports(
    registry: Registry,
    *,
    list_imports_use_case: ListImportsUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``imports`` against the import-listing use-case."""

    @registry.tool(name="imports")
    def imports(offset: int = 0, count: int = 100) -> ListImportsView:
        """List the module's imported symbols as a bounded page grouped by their
        originating library. ``offset`` skips that many imports from the start;
        ``count`` caps how many are returned (clamped to a server maximum). Each
        row carries the symbol name, its import-table address, the module it is
        drawn from, and its ordinal when the platform links by ordinal. The
        result carries the total count and a ``truncated`` flag so a caller can
        page through the whole table."""
        command = ListImportsCommand(offset=offset, count=count)
        result = run_use_case(executor, lambda: list_imports_use_case.execute(command))
        return list_imports_view(result.page)
