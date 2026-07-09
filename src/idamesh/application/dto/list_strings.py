"""Command/Result DTOs for ``list_strings``."""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.string_item import StringItem
from idamesh.domain.values.pagination import Page


@dataclass(frozen=True)
class ListStringsCommand:
    """Input for ``list_strings`` — an ``{offset, count}`` slice request."""

    offset: int = 0
    count: int = 100


@dataclass(frozen=True)
class ListStringsResult:
    """Output for ``list_strings`` — a page of extracted strings."""

    page: Page[StringItem]
