"""Catalog registration and wire-shape projection for ``get_bytes``.

The ``GetBytesView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`get_bytes_view` renders the read into that flat shape
(address as ``0x`` hex, the raw bytes as a lowercase hex string). The field names
mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.memory import GetBytesUseCase
from idamesh.application.dto.memory import GetBytesCommand
from idamesh.domain.entities.memory import ByteRead
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class GetBytesView(TypedDict):
    """Raw bytes read from one region."""

    address: str
    size: int
    bytes: str


def get_bytes_view(read: ByteRead) -> GetBytesView:
    """Project a :class:`ByteRead` into its wire shape."""
    return GetBytesView(
        address=read.address.hex(),
        size=read.size,
        bytes=read.data.hex(),
    )


def register_get_bytes(
    registry: Registry,
    *,
    get_bytes_use_case: GetBytesUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``get_bytes`` against the byte-read use-case."""

    @registry.tool(name="get_bytes")
    def get_bytes(address: str, size: int) -> GetBytesView:
        """Read ``size`` raw bytes starting at ``address``. The ``address`` may be
        a hexadecimal literal (``0x…``), a decimal literal, or a symbol name; it is
        resolved to the start of the region first. The result echoes the resolved
        ``address`` (``0x`` hex) and ``size``, and returns the ``bytes`` as a
        lowercase hex string. An out-of-range or unresolvable address, or an
        unreadable region, yields an error result rather than failing the protocol
        request."""
        command = GetBytesCommand(address=address, size=size)
        result = run_use_case(
            executor, lambda: get_bytes_use_case.execute(command)
        )
        return get_bytes_view(result.read)
