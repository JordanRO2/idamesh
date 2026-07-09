"""The memory gateway port: read raw bytes and strings from the database image.

One port serves all four memory tools. :meth:`read_bytes` returns the exact bytes
backing a region; the integer and global-value tools decode those bytes in the
use-case (endianness comes from the database metadata, keeping interpretation
pure). :meth:`read_string` returns a decoded string starting at an address, or
``None`` when no string is present. Byte order and signedness are *not* the
gateway's concern — it hands back raw bytes and leaves interpretation to the
application layer.
"""

from __future__ import annotations

from typing import Optional, Protocol

from idamesh.domain.values.address import Address


class MemoryGateway(Protocol):
    """Raw byte- and string-level reads over the loaded image."""

    def read_bytes(self, ea: Address, size: int) -> bytes:
        """Return the ``size`` bytes backing the region starting at ``ea``.

        The returned buffer is exactly the bytes present in the image at that
        range. Raises an error (surfaced by the caller as an ``isError`` result)
        when the region is unreadable or falls outside mapped memory.
        """
        ...

    def read_string(self, ea: Address, max_length: Optional[int]) -> Optional[str]:
        """Return the decoded string starting at ``ea``, or ``None`` if absent.

        Reads up to ``max_length`` bytes (``None`` = the server's own ceiling),
        auto-detecting the string's terminator and encoding. Returns ``None`` when
        no string literal is present at ``ea``.
        """
        ...
