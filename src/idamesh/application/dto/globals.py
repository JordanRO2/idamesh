"""Command/Result DTOs for ``list_globals``."""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.data import Global
from idamesh.domain.values.pagination import Page


@dataclass(frozen=True)
class ListGlobalsCommand:
    """Input for ``list_globals`` — an ``{offset, count}`` slice request."""

    offset: int = 0
    count: int = 100


@dataclass(frozen=True)
class ListGlobalsResult:
    """Output for ``list_globals`` — a page of globals."""

    page: Page[Global]
