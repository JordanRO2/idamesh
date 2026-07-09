"""The :class:`TextMatch` entity — one hit of a rendered-listing text search.

A match pairs the address of a disassembly line with the rendered text of that
line (control tags already stripped) in which the searched substring was found.
The *shape* (an address and the matching line per hit) is the interoperability
contract a client parses; wrapping it in a named value object — rather than a
bare ``(address, line)`` tuple — is our choice, so the match can later carry
per-hit context (column, section) without a shape change.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class TextMatch:
    """A single disassembly line whose rendered text contains the query."""

    address: Address
    line: str
