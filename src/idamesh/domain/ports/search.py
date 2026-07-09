"""The search gateway port: locate byte patterns in the database image."""

from __future__ import annotations

from typing import List, Protocol

from idamesh.domain.values.address import Address


class SearchGateway(Protocol):
    """Byte-pattern search over the loaded image, bounded by a match limit."""

    def find_bytes(self, pattern: str, limit: int) -> List[Address]:
        """Return up to ``limit`` addresses whose bytes match ``pattern``.

        ``pattern`` is an IDA-style hexadecimal byte pattern that may contain
        wildcards (for example ``"48 8B ?? 05"``), matched forward across the
        searchable image in address order. At most ``limit`` matches are
        returned; ``limit`` is assumed already clamped to a server maximum by the
        caller. Raises ``ValueError`` when ``pattern`` cannot be parsed.
        """
        ...
