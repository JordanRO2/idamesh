"""The listing-search gateway port: substring search over the rendered listing.

Where :class:`~idamesh.domain.ports.search.SearchGateway` matches raw bytes, this
port matches what IDA *displays*: it walks the defined items of the image,
renders each disassembly line to plain text (control tags stripped), and returns
the lines whose text contains a query substring. The search is case-insensitive
and bounded by a match limit. Each hit is a
:class:`~idamesh.domain.entities.text_match.TextMatch` pairing the line's address
with its rendered text.
"""

from __future__ import annotations

from typing import List, Protocol

from idamesh.domain.entities.text_match import TextMatch


class ListingSearchGateway(Protocol):
    """Case-insensitive substring search over the rendered disassembly listing."""

    def search(self, text: str, limit: int) -> List[TextMatch]:
        """Return up to ``limit`` listing lines whose rendered text contains ``text``.

        The image's defined items are walked in address order; each line is
        rendered to tag-free text and tested for a case-insensitive substring
        match against ``text``. At most ``limit`` matches are returned; ``limit``
        is assumed already clamped to a server maximum by the caller.
        """
        ...
