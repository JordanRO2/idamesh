"""Catalog registration and wire-shape projection for ``get_global_value``.

The ``GetGlobalValueView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`get_global_value_view` renders the resolved global's value
into that flat shape (address as ``0x`` hex). The field names mirror the
interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.memory import GetGlobalValueUseCase
from idamesh.application.dto.memory import (
    DEFAULT_INT_SIZE,
    GetGlobalValueCommand,
)
from idamesh.domain.entities.memory import GlobalValue
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class GetGlobalValueView(TypedDict):
    """The value of a named global read as an integer.

    ``value`` is carried as a base-10 **string**, not a JSON number — exactly as
    ``get_int`` does — so a full-width (up to 64-bit) decode survives the JSON
    round-trip without losing precision above 2**53 in a double-based client.
    """

    name: str
    address: str
    size: int
    signed: bool
    value: str
    hex: str


def get_global_value_view(value: GlobalValue) -> GetGlobalValueView:
    """Project a :class:`GlobalValue` into its wire shape.

    ``value`` is rendered as a decimal string so the full-width integer survives the
    JSON round-trip without precision loss.
    """
    return GetGlobalValueView(
        name=value.name,
        address=value.address.hex(),
        size=value.size,
        signed=value.signed,
        value=str(value.value),
        hex=value.hex,
    )


def register_get_global_value(
    registry: Registry,
    *,
    get_global_value_use_case: GetGlobalValueUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``get_global_value`` against the global-value-read use-case."""

    @registry.tool(name="get_global_value")
    def get_global_value(
        name: str, size: int = DEFAULT_INT_SIZE, signed: bool = False
    ) -> GetGlobalValueView:
        """Read the value of a named global as an integer. ``name`` may be a
        symbol name or an address (hexadecimal or decimal); it is resolved to the
        global first. ``size`` bytes are read and decoded under the database's byte
        order and, when ``signed`` is true, as a two's-complement value — exactly as
        ``get_int`` does. The result echoes the resolved ``name`` and ``address``
        (``0x`` hex), the ``size`` and ``signed`` interpretation, the decoded
        ``value``, and its ``hex`` rendering. An unresolvable name or unreadable
        region yields an error result rather than failing the protocol request."""
        command = GetGlobalValueCommand(name=name, size=size, signed=signed)
        result = run_use_case(
            executor, lambda: get_global_value_use_case.execute(command)
        )
        return get_global_value_view(result.value)
