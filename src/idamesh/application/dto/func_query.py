"""Command/Result DTOs for ``func_query``.

A filtered query over the :class:`~idamesh.domain.ports.functions.FunctionRepository`:
a case-insensitive name substring, an inclusive byte-size band, and tri-state
library/thunk flags, all optional, combined as a conjunction. The result is a
bounded, ``truncated``-flagged list of matched
:class:`~idamesh.domain.entities.function.Function` entities.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from idamesh.domain.entities.function import Function

#: Matches returned when a ``func_query`` client omits ``limit``.
DEFAULT_FUNC_QUERY_LIMIT: int = 100
#: Hard ceiling a requested ``func_query`` ``limit`` is clamped to.
MAX_FUNC_QUERY_LIMIT: int = 1000
#: Ceiling on functions scanned before the sweep stops.
MAX_FUNC_QUERY_SCAN: int = 200_000


@dataclass(frozen=True)
class FuncQueryCommand:
    """Input for ``func_query``.

    ``name`` is a case-insensitive substring of the function name (empty matches
    all). ``min_size`` / ``max_size`` bound the function's byte size inclusively; a
    ``max_size`` of ``0`` leaves the upper end unbounded. ``is_library`` /
    ``is_thunk`` are tri-state: ``None`` does not filter, ``True`` / ``False``
    require the flag to match. ``limit`` bounds the matches and is clamped to a
    server maximum.
    """

    name: str = ""
    min_size: int = 0
    max_size: int = 0
    is_library: Optional[bool] = None
    is_thunk: Optional[bool] = None
    limit: int = DEFAULT_FUNC_QUERY_LIMIT


@dataclass(frozen=True)
class FuncQueryResult:
    """Output for ``func_query`` — the matched functions."""

    matches: Tuple[Function, ...]
    truncated: bool = False
