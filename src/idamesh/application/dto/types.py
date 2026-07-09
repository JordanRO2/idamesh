"""Command/Result DTOs for the type tools ``type_query`` / ``type_inspect``.

``type_query`` filters the local type catalog by a case-insensitive name
substring and returns a bounded, ``truncated``-flagged list of matches projected
to name/kind/size. ``type_inspect`` resolves one type by name and returns its full
:class:`~idamesh.domain.entities.type_info.TypeInfo`, member layout included for
aggregates. An unknown type name is surfaced by the use-case as an error the
interface layer renders as an ``isError`` result.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.type_info import TypeInfo

#: Matches returned when a ``type_query`` client omits ``limit``.
DEFAULT_TYPE_QUERY_LIMIT: int = 100
#: Hard ceiling a requested ``type_query`` ``limit`` is clamped to.
MAX_TYPE_QUERY_LIMIT: int = 1000


@dataclass(frozen=True)
class TypeQueryCommand:
    """Input for ``type_query``.

    ``query`` is matched (case-insensitively) as a substring of each type's name;
    an empty ``query`` matches every named type. ``limit`` bounds how many matches
    are returned and is clamped to a server maximum.
    """

    query: str = ""
    limit: int = DEFAULT_TYPE_QUERY_LIMIT


@dataclass(frozen=True)
class TypeQueryResult:
    """Output for ``type_query`` — the query and the types it matched."""

    query: str
    matches: Tuple[TypeInfo, ...]
    truncated: bool = False


@dataclass(frozen=True)
class TypeInspectCommand:
    """Input for ``type_inspect`` — the ``name`` of the type to inspect."""

    name: str


@dataclass(frozen=True)
class TypeInspectResult:
    """Output for ``type_inspect`` — the resolved type's full definition."""

    type_info: TypeInfo
