"""Command/Result DTOs for ``imports_query``.

A filtered query over the :class:`~idamesh.domain.ports.imports.ImportRepository`:
a case-insensitive substring on the symbol name and another on the originating
module, combined as a conjunction. The result is a bounded, ``truncated``-flagged
list of matched :class:`~idamesh.domain.entities.imports.Import` entities.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.imports import Import

#: Matches returned when an ``imports_query`` client omits ``limit``.
DEFAULT_IMPORTS_QUERY_LIMIT: int = 100
#: Hard ceiling a requested ``imports_query`` ``limit`` is clamped to.
MAX_IMPORTS_QUERY_LIMIT: int = 1000
#: Ceiling on imported symbols scanned before the sweep stops.
MAX_IMPORTS_QUERY_SCAN: int = 100_000


@dataclass(frozen=True)
class ImportsQueryCommand:
    """Input for ``imports_query``.

    ``name`` is a case-insensitive substring of the imported symbol name and
    ``module`` a case-insensitive substring of its originating library; either
    empty leaves that axis unfiltered. ``limit`` bounds the matches and is clamped
    to a server maximum.
    """

    name: str = ""
    module: str = ""
    limit: int = DEFAULT_IMPORTS_QUERY_LIMIT


@dataclass(frozen=True)
class ImportsQueryResult:
    """Output for ``imports_query`` — the matched imported symbols."""

    matches: Tuple[Import, ...]
    truncated: bool = False
