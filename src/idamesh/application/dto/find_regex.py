"""Command/Result DTOs for ``find_regex``.

``find_regex`` reuses the extracted-string set (via ``StringsRepository``) and
filters it by a Python regular expression in the use-case, so its match rows are
the shared :class:`~idamesh.domain.entities.string_item.StringItem`; the view
projects only each match's address and value.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.string_item import StringItem

#: Matches returned when a client omits ``limit``.
DEFAULT_REGEX_LIMIT: int = 30
#: Hard ceiling a requested ``limit`` is clamped to.
MAX_REGEX_LIMIT: int = 500


@dataclass(frozen=True)
class FindRegexCommand:
    """Input for ``find_regex``.

    ``pattern`` is a Python regular expression matched (with ``re.search``)
    against each extracted string's value; ``limit`` bounds how many matches are
    returned and is clamped to a server maximum.
    """

    pattern: str
    limit: int = DEFAULT_REGEX_LIMIT


@dataclass(frozen=True)
class FindRegexResult:
    """Output for ``find_regex`` — the pattern and the strings it matched."""

    pattern: str
    matches: Tuple[StringItem, ...]
    truncated: bool = False
