"""Command/Result DTOs for ``find_bytes``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.byte_match import ByteMatch

#: Matches returned when a client omits ``limit``.
DEFAULT_MATCH_LIMIT: int = 1000
#: Hard ceiling a requested ``limit`` is clamped to.
MAX_MATCH_LIMIT: int = 10_000


@dataclass(frozen=True)
class FindBytesCommand:
    """Input for ``find_bytes``.

    ``pattern`` is an IDA-style hexadecimal byte pattern that may contain
    wildcards (for example ``"48 8B ?? 05"``). ``limit`` bounds how many matching
    addresses are returned and is clamped to a server maximum.
    """

    pattern: str
    limit: int = DEFAULT_MATCH_LIMIT


@dataclass(frozen=True)
class FindBytesResult:
    """Output for ``find_bytes`` — the pattern and the addresses it matched."""

    pattern: str
    matches: Tuple[ByteMatch, ...]
    truncated: bool = False
