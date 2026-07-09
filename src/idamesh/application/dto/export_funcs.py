"""Command/Result DTOs for ``export_funcs``.

``export_funcs`` reuses the function repository and projects each function to the
compact :class:`~idamesh.domain.entities.func_ref.FuncRef` (name + address),
returning a standard :class:`~idamesh.domain.values.pagination.Page` so a caller
can stream the whole function set into other tools.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.func_ref import FuncRef
from idamesh.domain.values.pagination import Page

#: Functions returned when a client omits ``count``.
DEFAULT_EXPORT_COUNT: int = 100


@dataclass(frozen=True)
class ExportFuncsCommand:
    """Input for ``export_funcs`` — an ``{offset, count}`` slice request."""

    offset: int = 0
    count: int = DEFAULT_EXPORT_COUNT


@dataclass(frozen=True)
class ExportFuncsResult:
    """Output for ``export_funcs`` — a page of compact function references."""

    page: Page[FuncRef]
