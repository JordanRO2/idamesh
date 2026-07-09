"""Command/Result DTOs for ``entity_query``.

A unified, filtered query over the three named-entity repositories (functions,
named globals, imports). ``kind`` selects which repositories are drawn from and
``query`` filters by a case-insensitive name substring; the result is a bounded,
``truncated``-flagged stream of :class:`~idamesh.domain.entities.named_entity.NamedEntity`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.named_entity import NamedEntity

#: Matches returned when an ``entity_query`` client omits ``limit``.
DEFAULT_ENTITY_QUERY_LIMIT: int = 100
#: Hard ceiling a requested ``entity_query`` ``limit`` is clamped to.
MAX_ENTITY_QUERY_LIMIT: int = 1000
#: Ceiling on entities scanned per selected repository before the sweep stops.
MAX_ENTITY_QUERY_SCAN: int = 100_000
#: The accepted ``kind`` selector values (``"any"`` draws from every repository).
ENTITY_KINDS: Tuple[str, ...] = ("any", "function", "global", "import")


@dataclass(frozen=True)
class EntityQueryCommand:
    """Input for ``entity_query``.

    ``query`` is a case-insensitive name substring (empty matches every name).
    ``kind`` restricts the search to one entity kind (``function`` / ``global`` /
    ``import``) or spans all three when ``"any"``. ``limit`` bounds the matches
    returned and is clamped to a server maximum.
    """

    query: str = ""
    kind: str = "any"
    limit: int = DEFAULT_ENTITY_QUERY_LIMIT


@dataclass(frozen=True)
class EntityQueryResult:
    """Output for ``entity_query`` — the matched named entities."""

    query: str
    kind: str
    matches: Tuple[NamedEntity, ...]
    truncated: bool = False
