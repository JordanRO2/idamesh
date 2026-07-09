"""Command/Result DTOs for ``search_structs``.

``search_structs`` filters the database's aggregate (struct/union) types by a
case-insensitive name substring and returns a bounded, ``truncated``-flagged list
of :class:`~idamesh.domain.entities.struct_summary.StructSummary` rows (name,
size, member count).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.struct_summary import StructSummary

#: Matches returned when a ``search_structs`` client omits ``limit``.
DEFAULT_SEARCH_STRUCTS_LIMIT: int = 100
#: Hard ceiling a requested ``search_structs`` ``limit`` is clamped to.
MAX_SEARCH_STRUCTS_LIMIT: int = 1000


@dataclass(frozen=True)
class SearchStructsCommand:
    """Input for ``search_structs``.

    ``query`` is matched (case-insensitively) as a substring of each aggregate
    type's name; an empty ``query`` matches every struct/union. ``limit`` bounds
    how many matches are returned and is clamped to a server maximum.
    """

    query: str = ""
    limit: int = DEFAULT_SEARCH_STRUCTS_LIMIT


@dataclass(frozen=True)
class SearchStructsResult:
    """Output for ``search_structs`` — the query and the structs it matched."""

    query: str
    matches: Tuple[StructSummary, ...]
    truncated: bool = False
