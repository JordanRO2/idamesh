"""Command/Result DTOs for ``lookup_funcs``.

``lookup_funcs`` reuses the function repository and filters the function set by a
case-insensitive name substring in the use-case, returning the compact
:class:`~idamesh.domain.entities.func_ref.FuncRef` (name + address) for each hit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.func_ref import FuncRef

#: Matches returned when a client omits ``limit``.
DEFAULT_LOOKUP_LIMIT: int = 100
#: Hard ceiling a requested ``limit`` is clamped to.
MAX_LOOKUP_LIMIT: int = 1000


@dataclass(frozen=True)
class LookupFuncsCommand:
    """Input for ``lookup_funcs``.

    ``query`` is matched (case-insensitively) as a substring of each function's
    name; ``limit`` bounds how many matches are returned and is clamped to a
    server maximum.
    """

    query: str
    limit: int = DEFAULT_LOOKUP_LIMIT


@dataclass(frozen=True)
class LookupFuncsResult:
    """Output for ``lookup_funcs`` — the query and the functions it matched."""

    query: str
    matches: Tuple[FuncRef, ...]
    truncated: bool = False
