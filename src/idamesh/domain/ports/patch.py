"""The patch gateway port: write raw bytes, and assemble one instruction.

Shared write surface for the ``patch`` and ``patch_asm`` tools. :meth:`patch_bytes`
overwrites the byte(s) at an effective address with a caller-supplied buffer and
reports how many were written, so ``patch`` can echo the patched ``size``.
:meth:`assemble` encodes a single instruction from assembly text using the target
architecture's own assembler and returns the resulting machine bytes *without*
writing them, so ``patch_asm`` can assemble, patch, and report the encoding in one
flow. Text the architecture cannot assemble raises a domain error the caller
surfaces as an ``isError`` result rather than a crash — assembly never falls back
to an external engine. Encoding/writing are the adapter's SDK-level job; this port
only fixes the contract.
"""

from __future__ import annotations

from typing import Protocol

from idamesh.domain.values.address import Address


class PatchGateway(Protocol):
    """Write-side access to the raw bytes at an address, plus one-shot assembly."""

    def patch_bytes(self, ea: Address, data: bytes) -> int:
        """Overwrite the bytes at ``ea`` with ``data``; return the count written.

        ``data`` is written verbatim starting at ``ea``. The returned integer is
        the number of bytes patched (the length of ``data`` on success). Raises an
        error (surfaced by the caller as an ``isError`` result) when the region is
        not writable.
        """
        ...

    def assemble(self, ea: Address, text: str) -> bytes:
        """Assemble the single instruction ``text`` at ``ea`` and return its bytes.

        ``text`` is one line of assembly for the database's architecture, encoded
        as if placed at ``ea`` (so ``ea``-relative operands resolve correctly). The
        resulting machine bytes are returned *unwritten*. Raises an error (surfaced
        by the caller as an ``isError`` result) when the architecture's assembler
        cannot encode ``text`` — assembly is never delegated to an external engine.
        """
        ...
