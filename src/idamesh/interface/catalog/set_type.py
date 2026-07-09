"""Catalog registration and wire-shape projection for ``set_type`` (mutating).

The ``SetTypeView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`set_type_view` renders the completed application into that
flat shape (address as ``0x`` hex, ``ok`` always true on success). The tool is
marked ``@registry.mutating`` so its advertised ``readOnlyHint`` is ``false``. The
field names mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.set_type import SetTypeUseCase
from idamesh.application.dto.set_type import SetTypeCommand
from idamesh.domain.entities.type_application import TypeApplication
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class SetTypeView(TypedDict):
    """The outcome of one ``set_type`` call."""

    address: str
    name: str
    type: str
    ok: bool


def set_type_view(application: TypeApplication) -> SetTypeView:
    """Project a :class:`TypeApplication` into its wire shape."""
    return SetTypeView(
        address=application.address.hex(),
        name=application.name,
        type=application.type,
        ok=True,
    )


def register_set_type(
    registry: Registry,
    *,
    set_type_use_case: SetTypeUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``set_type`` against the set-type use-case (a mutating tool)."""

    @registry.tool(name="set_type")
    @registry.mutating
    def set_type(address: str, type: str) -> SetTypeView:
        """Apply the C declaration ``type`` to the function or data item at
        ``address``. The ``address`` may be a hexadecimal literal (``0x…``), a
        decimal literal, or a symbol name; it is resolved first. ``type`` is a C
        declaration or function prototype (e.g. ``int f(char *)`` or ``unsigned
        int``) parsed against the local type library and applied at the address.
        The result reports the resolved ``address`` (``0x`` hex), the item ``name``
        after the change, the ``type`` applied, and ``ok``. This modifies the
        database. An unparseable declaration, a type that cannot be applied at the
        address, or an unresolvable address yields an error result rather than
        failing the protocol request."""
        command = SetTypeCommand(address=address, type=type)
        result = run_mutation(
            executor, lambda: set_type_use_case.execute(command)
        )
        return set_type_view(result.application)
