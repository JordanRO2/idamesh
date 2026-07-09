"""Patch entities: :class:`BytePatch` and :class:`AsmPatch`.

Back the ``patch`` and ``patch_asm`` tools. A :class:`BytePatch` records one
completed raw-byte write at a resolved address — how many bytes landed. An
:class:`AsmPatch` records one completed assemble-and-write — the encoded ``data``
that was assembled from the caller's text and the ``size`` it occupies. The
*shapes* (the field sets a client parses) are the interoperability contract;
holding each outcome in an immutable record is ours. Success is implicit in the
record's existence — a refused patch or an un-assemblable instruction never
produces one; it surfaces as an error at the boundary instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class BytePatch:
    """A completed raw-byte patch: the address and the number of bytes written."""

    address: Address
    size: int


@dataclass(frozen=True)
class AsmPatch:
    """A completed assemble-and-patch: the address, the encoded bytes, and size."""

    address: Address
    data: bytes
    size: int
