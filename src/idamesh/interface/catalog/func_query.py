"""Catalog registration and wire-shape projection for ``func_query``.

The ``FuncMatchView`` / ``FuncQueryView`` ``TypedDict``s give the schema compiler an
object-rooted ``outputSchema``; :func:`func_query_view` renders each matched
:class:`~idamesh.domain.entities.function.Function` into that flat shape (address as
``0x`` hex). The field names mirror the interoperability contract; the projection
is ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.func_query import FuncQueryUseCase
from idamesh.application.dto.func_query import (
    DEFAULT_FUNC_QUERY_LIMIT,
    FuncQueryCommand,
    FuncQueryResult,
)
from idamesh.domain.entities.function import Function
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class FuncMatchView(TypedDict):
    """One matched function in a ``func_query`` result."""

    name: str
    address: str
    size: int
    is_library: bool
    is_thunk: bool


class FuncQueryView(TypedDict):
    """The functions that matched the query."""

    matches: List[FuncMatchView]
    truncated: bool


def func_match_view(func: Function) -> FuncMatchView:
    """Project one :class:`Function` into its wire shape."""
    return FuncMatchView(
        name=func.name,
        address=func.ea.hex(),
        size=func.size,
        is_library=func.is_library,
        is_thunk=func.is_thunk,
    )


def func_query_view(result: FuncQueryResult) -> FuncQueryView:
    """Project a ``func_query`` result into its wire shape."""
    return FuncQueryView(
        matches=[func_match_view(func) for func in result.matches],
        truncated=result.truncated,
    )


def register_func_query(
    registry: Registry,
    *,
    func_query_use_case: FuncQueryUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``func_query`` against the function-filter use-case."""

    @registry.tool(name="func_query")
    def func_query(
        name: str = "",
        min_size: int = 0,
        max_size: int = 0,
        is_library: Optional[bool] = None,
        is_thunk: Optional[bool] = None,
        limit: int = DEFAULT_FUNC_QUERY_LIMIT,
    ) -> FuncQueryView:
        """Filter the database's functions by a conjunction of predicates. ``name``
        matches a case-insensitive substring of the function name (empty matches
        all). ``min_size`` and ``max_size`` bound the function's byte size
        inclusively; a ``max_size`` of ``0`` leaves the upper end unbounded.
        ``is_library`` and ``is_thunk`` are tri-state — omit (null) to ignore the
        flag, or pass ``true`` / ``false`` to require it. ``limit`` caps how many
        matches are returned (clamped to a server maximum). Each match carries the
        function ``name``, entry ``address`` (``0x``-hex), byte ``size``, and its
        ``is_library`` / ``is_thunk`` flags; ``truncated`` is set when the cap
        elided further matches. Read-only."""
        command = FuncQueryCommand(
            name=name,
            min_size=min_size,
            max_size=max_size,
            is_library=is_library,
            is_thunk=is_thunk,
            limit=limit,
        )
        result = run_use_case(
            executor, lambda: func_query_use_case.execute(command)
        )
        return func_query_view(result)
