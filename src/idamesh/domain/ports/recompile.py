"""The recompile gateway port: invalidate the decompiler cache for a function.

Backs the ``force_recompile`` tool. :meth:`recompile` discards any cached Hex-Rays
decompilation for the function covering an effective address, so the next
``decompile`` regenerates fresh pseudocode after type, name, operand, or data
edits. Kept as its own port so the write-side cache-invalidation surface stays
disjoint from the read-side
:class:`~idamesh.domain.ports.decompiler.DecompilerGateway`. An address in no
function, or an unavailable decompiler, raises a domain error the caller surfaces
as an ``isError`` result. The SDK-level cache clear is the adapter's job; this port
only fixes the contract.
"""

from __future__ import annotations

from typing import Protocol

from idamesh.domain.values.address import Address


class RecompileGateway(Protocol):
    """Write-side invalidation of the decompiler cache for a function."""

    def recompile(self, ea: Address) -> None:
        """Invalidate the cached decompilation of the function covering ``ea``.

        The stale ``cfunc`` for the enclosing function is dropped so the next
        decompilation is regenerated from the current database state. Raises an
        error (surfaced by the caller as an ``isError`` result) when ``ea`` lies in
        no function or the decompiler is unavailable.
        """
        ...
