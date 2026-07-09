"""Catalog registration and wire-shape projection for ``export_funcs``.

The ``FuncRefView`` / ``ExportFuncsView`` ``TypedDict``s give the schema compiler
an object-rooted ``outputSchema``; :func:`export_funcs_view` renders the page of
compact function references into that flat shape (address as ``0x`` hex). The
field names mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.export_funcs import ExportFuncsUseCase
from idamesh.application.dto.export_funcs import (
    DEFAULT_EXPORT_COUNT,
    ExportFuncsCommand,
)
from idamesh.domain.entities.func_ref import FuncRef
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.domain.values.pagination import Page
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class FuncRefView(TypedDict):
    """One compact function reference row in an ``export_funcs`` page."""

    name: str
    address: str


class ExportFuncsView(TypedDict):
    """A page of :class:`FuncRefView` rows plus continuation metadata."""

    items: List[FuncRefView]
    offset: int
    count: int
    total: Optional[int]
    truncated: bool
    next_cursor: Optional[str]


def func_ref_view(ref: FuncRef) -> FuncRefView:
    """Project one :class:`FuncRef` into its wire shape."""
    return FuncRefView(name=ref.name, address=ref.address.hex())


def export_funcs_view(page: Page[FuncRef]) -> ExportFuncsView:
    """Project a page of function references into its wire shape."""
    return ExportFuncsView(
        items=[func_ref_view(ref) for ref in page.items],
        offset=page.offset,
        count=page.count,
        total=page.total,
        truncated=page.truncated,
        next_cursor=page.next_cursor,
    )


def register_export_funcs(
    registry: Registry,
    *,
    export_funcs_use_case: ExportFuncsUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``export_funcs`` against the bulk-function-export use-case."""

    @registry.tool(name="export_funcs")
    def export_funcs(
        offset: int = 0, count: int = DEFAULT_EXPORT_COUNT
    ) -> ExportFuncsView:
        """Export the database's functions as a compact bulk list suitable for
        feeding into other tools. ``offset`` skips that many functions from the
        start; ``count`` caps how many are returned (clamped to a server maximum).
        Each row carries just the function ``name`` and its entry ``address``
        (``0x`` hex). The result carries the ``total`` function count and a
        ``truncated`` flag, plus a ``next_cursor`` when more remain, so a caller
        can page through the whole set. Read-only."""
        command = ExportFuncsCommand(offset=offset, count=count)
        result = run_use_case(
            executor, lambda: export_funcs_use_case.execute(command)
        )
        return export_funcs_view(result.page)
