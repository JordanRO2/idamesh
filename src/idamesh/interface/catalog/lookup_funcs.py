"""Catalog registration and wire-shape projection for ``lookup_funcs``.

The ``LookupMatchView`` / ``LookupFuncsView`` ``TypedDict``s give the schema
compiler an object-rooted ``outputSchema``; :func:`lookup_funcs_view` renders each
matched function into that flat shape (address as ``0x`` hex). The field names
mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, TypedDict

from idamesh.application.contexts.lookup_funcs import LookupFuncsUseCase
from idamesh.application.dto.lookup_funcs import (
    DEFAULT_LOOKUP_LIMIT,
    LookupFuncsCommand,
    LookupFuncsResult,
)
from idamesh.domain.entities.func_ref import FuncRef
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class LookupMatchView(TypedDict):
    """One matched function in a ``lookup_funcs`` result."""

    name: str
    address: str


class LookupFuncsView(TypedDict):
    """The functions whose name contained ``query``."""

    query: str
    matches: List[LookupMatchView]
    truncated: bool


def lookup_match_view(ref: FuncRef) -> LookupMatchView:
    """Project one matched :class:`FuncRef` into its wire shape."""
    return LookupMatchView(name=ref.name, address=ref.address.hex())


def lookup_funcs_view(result: LookupFuncsResult) -> LookupFuncsView:
    """Project a ``lookup_funcs`` result into its wire shape."""
    return LookupFuncsView(
        query=result.query,
        matches=[lookup_match_view(ref) for ref in result.matches],
        truncated=result.truncated,
    )


def register_lookup_funcs(
    registry: Registry,
    *,
    lookup_funcs_use_case: LookupFuncsUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``lookup_funcs`` against the function-name-search use-case."""

    @registry.tool(name="lookup_funcs")
    def lookup_funcs(query: str, limit: int = DEFAULT_LOOKUP_LIMIT) -> LookupFuncsView:
        """Find functions whose name contains ``query`` (case-insensitive).
        ``limit`` caps how many matches are returned (clamped to a server
        maximum). The result echoes the ``query`` and lists each match's function
        ``name`` and entry ``address`` (``0x`` hex), with ``truncated`` set when
        the cap elided further matches. Read-only."""
        command = LookupFuncsCommand(query=query, limit=limit)
        result = run_use_case(
            executor, lambda: lookup_funcs_use_case.execute(command)
        )
        return lookup_funcs_view(result)
