"""Catalog registration for ``list_globals``."""

from __future__ import annotations

from idamesh.application.contexts.globals import ListGlobalsUseCase
from idamesh.application.dto.globals import ListGlobalsCommand
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.catalog.views import ListGlobalsView, list_globals_view
from idamesh.interface.mcp.registry import Registry


def register_globals(
    registry: Registry,
    *,
    list_globals_use_case: ListGlobalsUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``list_globals`` against the global-listing use-case."""

    @registry.tool(name="list_globals")
    def list_globals(offset: int = 0, count: int = 100) -> ListGlobalsView:
        """List the database's named global (data) symbols in address order as a
        bounded page. ``offset`` skips that many globals from the start; ``count``
        caps how many are returned (clamped to a server maximum). Each row carries
        the symbol name, its address, item size in bytes, and its declared type
        when known. The result carries the total count and a ``truncated`` flag so
        a caller can page through the whole set."""
        command = ListGlobalsCommand(offset=offset, count=count)
        result = run_use_case(executor, lambda: list_globals_use_case.execute(command))
        return list_globals_view(result.page)
