"""Command/Result DTOs for ``search_text``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.text_match import TextMatch

#: Matches returned when a client omits ``limit``.
DEFAULT_SEARCH_TEXT_LIMIT: int = 30
#: Hard ceiling a requested ``limit`` is clamped to.
MAX_SEARCH_TEXT_LIMIT: int = 500


@dataclass(frozen=True)
class SearchTextCommand:
    """Input for ``search_text``.

    ``text`` is the substring matched (case-insensitively) against each rendered
    disassembly line; ``limit`` bounds how many matches are returned and is
    clamped to a server maximum.
    """

    text: str
    limit: int = DEFAULT_SEARCH_TEXT_LIMIT


@dataclass(frozen=True)
class SearchTextResult:
    """Output for ``search_text`` — the query and the lines it matched."""

    text: str
    matches: Tuple[TextMatch, ...]
    truncated: bool = False
