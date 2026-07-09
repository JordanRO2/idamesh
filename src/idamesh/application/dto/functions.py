"""Command/Result DTOs for ``list_funcs``."""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.function import Function
from idamesh.domain.values.pagination import Page


@dataclass(frozen=True)
class ListFuncsCommand:
    """Input for ``list_funcs`` — an ``{offset, count}`` slice request."""

    offset: int = 0
    count: int = 100


@dataclass(frozen=True)
class ListFuncsResult:
    """Output for ``list_funcs`` — a page of functions."""

    page: Page[Function]
