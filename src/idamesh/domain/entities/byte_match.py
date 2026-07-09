"""The :class:`ByteMatch` entity — one hit of a byte-pattern search.

A match records the address at which a searched byte pattern was found. The
*shape* (an address per hit) is the interoperability contract a client parses;
wrapping it in a named value object — rather than passing a bare address — is our
choice, so the match set can later carry per-hit context without a shape change.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class ByteMatch:
    """A single address at which a byte pattern matched."""

    address: Address
