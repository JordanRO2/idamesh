"""Catalog registration for ``list_funcs``."""

from __future__ import annotations

from idamesh.application.contexts.functions import ListFuncsUseCase
from idamesh.application.dto.functions import ListFuncsCommand
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.catalog.views import ListFuncsView, list_funcs_view
from idamesh.interface.mcp.registry import Registry


def register_functions(
    registry: Registry,
    *,
    list_funcs_use_case: ListFuncsUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``list_funcs`` against the function-listing use-case."""

    @registry.tool(name="list_funcs")
    def list_funcs(offset: int = 0, count: int = 100) -> ListFuncsView:
        """List the database's functions in address order as a bounded page.
        ``offset`` skips that many functions from the start; ``count`` caps how
        many are returned (clamped to a server maximum). The result carries the
        total function count and a ``truncated`` flag so a caller can page through
        the whole set."""
        command = ListFuncsCommand(offset=offset, count=count)
        result = run_use_case(executor, lambda: list_funcs_use_case.execute(command))
        return list_funcs_view(result.page)
