"""Command/Result DTOs for ``imports``."""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.imports import Import
from idamesh.domain.values.pagination import Page


@dataclass(frozen=True)
class ListImportsCommand:
    """Input for ``imports`` — an ``{offset, count}`` slice request."""

    offset: int = 0
    count: int = 100


@dataclass(frozen=True)
class ListImportsResult:
    """Output for ``imports`` — a page of imported symbols."""

    page: Page[Import]
