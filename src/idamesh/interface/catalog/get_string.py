"""Catalog registration and wire-shape projection for ``get_string``.

The ``GetStringView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`get_string_view` renders the read into that flat shape
(address as ``0x`` hex). The field names mirror the interoperability contract; the
projection is ours.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.memory import GetStringUseCase
from idamesh.application.dto.memory import (
    DEFAULT_STRING_MAX_LENGTH,
    GetStringCommand,
)
from idamesh.domain.entities.memory import StringRead
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class GetStringView(TypedDict):
    """One string read from memory."""

    address: str
    value: str
    length: int


def get_string_view(read: StringRead) -> GetStringView:
    """Project a :class:`StringRead` into its wire shape."""
    return GetStringView(
        address=read.address.hex(),
        value=read.value,
        length=read.length,
    )


def register_get_string(
    registry: Registry,
    *,
    get_string_use_case: GetStringUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``get_string`` against the string-read use-case."""

    @registry.tool(name="get_string")
    def get_string(
        address: str, max_length: int = DEFAULT_STRING_MAX_LENGTH
    ) -> GetStringView:
        """Read a string starting at ``address``. The ``address`` may be a
        hexadecimal literal (``0x…``), a decimal literal, or a symbol name; it is
        resolved first. At most ``max_length`` bytes are scanned, auto-detecting
        the terminator and encoding. The result reports the resolved ``address``
        (``0x`` hex), the decoded ``value``, and its byte ``length``. An
        out-of-range or unresolvable address, or the absence of a string, yields an
        error result rather than failing the protocol request."""
        command = GetStringCommand(address=address, max_length=max_length)
        result = run_use_case(
            executor, lambda: get_string_use_case.execute(command)
        )
        return get_string_view(result.read)
