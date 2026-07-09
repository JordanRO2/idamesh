"""The find_bytes use-case."""

from __future__ import annotations

from idamesh.application.dto.find_bytes import (
    MAX_MATCH_LIMIT,
    FindBytesCommand,
    FindBytesResult,
)
from idamesh.domain.entities.byte_match import ByteMatch
from idamesh.domain.ports.search import SearchGateway


class FindBytesUseCase:
    """Search the image for a byte pattern and return the matching addresses.

    Clamps the requested match ``limit`` to :data:`MAX_MATCH_LIMIT` so an
    oversized request can never make the scan unbounded, delegates the search to
    the :class:`~idamesh.domain.ports.search.SearchGateway`, and reports whether
    the returned set was capped by the limit (``truncated``).
    """

    def __init__(self, search: SearchGateway) -> None:
        self._search = search

    def execute(self, command: FindBytesCommand) -> FindBytesResult:
        """Clamp ``command.limit``, run the pattern search, and wrap the hits.

        The requested match budget is bounded to :data:`MAX_MATCH_LIMIT` before
        it reaches the gateway. Truncation is inferred from the returned length:
        a match set that exactly fills the clamped limit means the search stopped
        on the cap and further matches may exist, whereas a shorter set means the
        whole image was scanned and nothing was elided. An unparseable pattern
        surfaces as an error the interface layer renders as an ``isError`` result.
        """
        limit = min(command.limit, MAX_MATCH_LIMIT)
        if limit < 0:
            limit = 0
        addresses = self._search.find_bytes(command.pattern, limit)
        matches = tuple(ByteMatch(address=address) for address in addresses)
        # A set that exactly fills the (clamped) budget was stopped on the cap, so
        # further matches may exist; a shorter set means the whole image was
        # scanned. A zero budget is never a truncation — nothing was asked for.
        truncated = limit > 0 and len(matches) >= limit
        return FindBytesResult(
            pattern=command.pattern,
            matches=matches,
            truncated=truncated,
        )
