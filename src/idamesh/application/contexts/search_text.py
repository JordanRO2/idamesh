"""The ``search_text`` use-case.

Clamps the requested match ``limit`` to :data:`MAX_SEARCH_TEXT_LIMIT` so an
oversized request can never make the walk unbounded, delegates the rendered-listing
substring scan to the :class:`~idamesh.domain.ports.listing_search.ListingSearchGateway`,
and reports whether the returned set was capped (``truncated``).
"""

from __future__ import annotations

from idamesh.application.dto.search_text import (
    MAX_SEARCH_TEXT_LIMIT,
    SearchTextCommand,
    SearchTextResult,
)
from idamesh.domain.ports.listing_search import ListingSearchGateway


class SearchTextUseCase:
    """Search the rendered disassembly listing for a substring."""

    def __init__(self, listing: ListingSearchGateway) -> None:
        self._listing = listing

    def execute(self, command: SearchTextCommand) -> SearchTextResult:
        """Clamp ``command.limit``, run the listing search, and wrap the hits.

        The match budget is bounded to :data:`MAX_SEARCH_TEXT_LIMIT` before it
        reaches the gateway, so an oversized request can never make the walk
        unbounded. Truncation is inferred from the returned length: a set that
        exactly fills the clamped limit was stopped on the cap and further
        matches may exist, whereas a shorter set means the whole listing was
        scanned. A zero (or negative, clamped to zero) budget returns nothing
        and is never truncated.
        """
        limit = _clamp(command.limit)
        matches = self._listing.search(command.text, limit)
        truncated = limit > 0 and len(matches) >= limit
        return SearchTextResult(
            text=command.text,
            matches=tuple(matches),
            truncated=truncated,
        )


def _clamp(limit: int) -> int:
    """Bound a requested match budget to ``[0, MAX_SEARCH_TEXT_LIMIT]``."""
    if limit < 0:
        return 0
    if limit > MAX_SEARCH_TEXT_LIMIT:
        return MAX_SEARCH_TEXT_LIMIT
    return limit
