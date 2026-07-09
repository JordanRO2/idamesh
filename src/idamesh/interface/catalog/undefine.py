"""Catalog registration and wire-shape projection for ``undefine`` (destructive).

The ``UndefineView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`undefine_view` renders the completed reversion into that
flat shape (address as ``0x`` hex, ``ok`` always true on success). The tool is
marked ``@registry.destructive`` — it discards existing code/data definitions — so
its advertised ``readOnlyHint`` is ``false`` and ``destructiveHint`` is ``true``.
The field names mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.define_func import UndefineUseCase
from idamesh.application.dto.define_func import UndefineCommand
from idamesh.domain.entities.code_definition import Undefinition
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class UndefineView(TypedDict):
    """The outcome of one ``undefine`` call."""

    address: str
    ok: bool


def undefine_view(undefinition: Undefinition) -> UndefineView:
    """Project an :class:`Undefinition` into its wire shape."""
    return UndefineView(
        address=undefinition.address.hex(),
        ok=True,
    )


def register_undefine(
    registry: Registry,
    *,
    undefine_use_case: UndefineUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``undefine`` against the undefine use-case (a destructive tool)."""

    @registry.tool(name="undefine")
    @registry.destructive
    def undefine(address: str) -> UndefineView:
        """Undefine the item at ``address``, reverting it to raw bytes. The
        ``address`` may be a hexadecimal literal (``0x…``), a decimal literal, or a
        symbol name; it is resolved first. The function, code, or data definition
        covering the address is discarded. The result reports the resolved
        ``address`` (``0x`` hex) and ``ok``. This modifies the database and
        destroys the existing definition at the address. An address with nothing to
        undefine, or an unresolvable address, yields an error result rather than
        failing the protocol request."""
        command = UndefineCommand(address=address)
        result = run_mutation(
            executor, lambda: undefine_use_case.execute(command)
        )
        return undefine_view(result.undefinition)
