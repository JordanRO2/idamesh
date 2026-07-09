"""Command/Result DTOs for ``find_dangerous_callers``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.dangerous_caller import DangerousApiMatch

#: Call sites returned when a client omits ``limit``.
DEFAULT_CALLER_LIMIT: int = 200
#: Hard ceiling a requested ``limit`` is clamped to.
MAX_CALLER_LIMIT: int = 2000


@dataclass(frozen=True)
class FindDangerousCallersCommand:
    """Input for ``find_dangerous_callers``.

    ``limit`` bounds how many call sites are returned across every dangerous
    import and is clamped to a server maximum.
    """

    limit: int = DEFAULT_CALLER_LIMIT


@dataclass(frozen=True)
class FindDangerousCallersResult:
    """Output for ``find_dangerous_callers`` — dangerous imports and their callers."""

    matches: Tuple[DangerousApiMatch, ...]
    truncated: bool = False
