"""The :class:`CryptoMatch` entity — one crypto-constant hit in the image.

A match records *where* a known cryptographic constant was found (``address``),
*which* algorithm that constant belongs to (``algorithm``), and *which* named
constant matched (``constant`` — an S-box, an initialization vector, a
polynomial, an alphabet, …). The constant *values* are published algorithmic
facts; the pairing of a value with an address, and the field selection here, are
our modelling. Bundling the hit in a named value object (rather than a bare
address) lets the match set carry the identifying evidence without a shape
change.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class CryptoMatch:
    """A single address at which a known crypto constant was recognized."""

    address: Address
    algorithm: str
    constant: str
