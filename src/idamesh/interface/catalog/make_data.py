"""Catalog registration and wire-shape projection for ``make_data`` (mutating).

The ``MakeDataView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`make_data_view` renders the completed definition into that
flat shape (address as ``0x`` hex, ``ok`` always true on success). The tool is
marked ``@registry.mutating`` so its advertised ``readOnlyHint`` is ``false``. The
field names mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.make_data import MakeDataUseCase
from idamesh.application.dto.make_data import MakeDataCommand
from idamesh.domain.entities.data_definition import DataDefinition
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class MakeDataView(TypedDict):
    """The outcome of one ``make_data`` call."""

    address: str
    type: str
    size: int
    ok: bool


def make_data_view(definition: DataDefinition) -> MakeDataView:
    """Project a :class:`DataDefinition` into its wire shape."""
    return MakeDataView(
        address=definition.address.hex(),
        type=definition.type,
        size=definition.size,
        ok=True,
    )


def register_make_data(
    registry: Registry,
    *,
    make_data_use_case: MakeDataUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``make_data`` against the make-data use-case (a mutating tool)."""

    @registry.tool(name="make_data")
    @registry.mutating
    def make_data(address: str, type: str = "", size: int = 0) -> MakeDataView:
        """Define a data item at ``address``. The ``address`` may be a hexadecimal
        literal (``0x…``), a decimal literal, or a symbol name; it is resolved
        first. Supply a C ``type`` declaration (e.g. ``"int"`` or ``"char[16]"``)
        to define a typed item sized to that type; otherwise supply a ``size`` in
        bytes (1/2/4/8 → byte/word/dword/qword) to define a primitive item. At
        least one of ``type`` or ``size`` must be given. The result reports the
        resolved ``address`` (``0x`` hex), the ``type`` in force afterward, the
        item ``size`` in bytes, and ``ok``. This modifies the database. An
        unparseable declaration, an unsupported size, a request with neither a type
        nor a positive size, or an unresolvable address yields an error result
        rather than failing the protocol request."""
        command = MakeDataCommand(address=address, type=type, size=size)
        result = run_mutation(
            executor, lambda: make_data_use_case.execute(command)
        )
        return make_data_view(result.definition)
