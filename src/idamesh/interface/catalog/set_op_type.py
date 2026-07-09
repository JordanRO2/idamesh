"""Catalog registration and wire-shape projection for ``set_op_type`` (mutating).

The ``SetOpTypeView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`set_op_type_view` renders the completed change into that
flat shape (address as ``0x`` hex, ``ok`` always true on success). The tool is
marked ``@registry.mutating`` so its advertised ``readOnlyHint`` is ``false``. The
field names mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.set_op_type import SetOpTypeUseCase
from idamesh.application.dto.set_op_type import SetOpTypeCommand
from idamesh.domain.entities.operand_type import OperandTypeSetting
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class SetOpTypeView(TypedDict):
    """The outcome of one ``set_op_type`` call."""

    address: str
    operand: int
    type: str
    ok: bool


def set_op_type_view(setting: OperandTypeSetting) -> SetOpTypeView:
    """Project an :class:`OperandTypeSetting` into its wire shape."""
    return SetOpTypeView(
        address=setting.address.hex(),
        operand=setting.operand,
        type=setting.type,
        ok=True,
    )


def register_set_op_type(
    registry: Registry,
    *,
    set_op_type_use_case: SetOpTypeUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``set_op_type`` against the set-op-type use-case (a mutating tool)."""

    @registry.tool(name="set_op_type")
    @registry.mutating
    def set_op_type(address: str, operand: int, type: str) -> SetOpTypeView:
        """Set the display representation of an instruction operand. The ``address``
        may be a hexadecimal literal (``0x…``), a decimal literal, or a symbol name;
        it is resolved first and should point at an instruction. ``operand`` is the
        zero-based operand index. ``type`` names the representation to apply — a
        numeric base (``"hex"``, ``"dec"``, ``"oct"``, ``"bin"``, ``"char"``) or
        ``"offset"``. The result reports the resolved ``address`` (``0x`` hex), the
        ``operand`` index, the ``type`` in force afterward, and ``ok``. This modifies
        the database. An out-of-range operand, an unknown type, or an unresolvable
        address yields an error result rather than failing the protocol request."""
        command = SetOpTypeCommand(address=address, operand=operand, type=type)
        result = run_mutation(
            executor, lambda: set_op_type_use_case.execute(command)
        )
        return set_op_type_view(result.setting)
