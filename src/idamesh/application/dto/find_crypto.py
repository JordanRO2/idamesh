"""Command/Result DTOs for ``find_crypto``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.crypto_match import CryptoMatch

#: Matches returned when a client omits ``limit``.
DEFAULT_MATCH_LIMIT: int = 64
#: Hard ceiling a requested ``limit`` is clamped to.
MAX_MATCH_LIMIT: int = 1000


@dataclass(frozen=True)
class FindCryptoCommand:
    """Input for ``find_crypto``.

    ``limit`` bounds how many constant matches are returned across the whole
    signature table and is clamped to a server maximum.
    """

    limit: int = DEFAULT_MATCH_LIMIT


@dataclass(frozen=True)
class FindCryptoResult:
    """Output for ``find_crypto`` — the crypto constants recognized in the image."""

    matches: Tuple[CryptoMatch, ...]
    truncated: bool = False
