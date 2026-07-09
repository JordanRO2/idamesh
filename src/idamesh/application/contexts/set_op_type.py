"""The ``set_op_type`` use-case: set an operand's display type at an address.

Resolves the polymorphic selector against the database gateway (mirroring the read
tools), validates the operand index and the requested display kind, then routes the
change through the :class:`~idamesh.domain.ports.operand.OperandGateway`, which
returns the representation actually in force. The operand-index and non-empty-kind
guards are the application's; the SDK-level operand tagging is the gateway's.
"""

from __future__ import annotations

from idamesh.application.dto.set_op_type import SetOpTypeCommand, SetOpTypeResult
from idamesh.domain.entities.operand_type import OperandTypeSetting
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.operand import OperandGateway
from idamesh.domain.values.address import Selector


def _require_operand(operand: int) -> int:
    """Return ``operand`` if it is a non-negative integer, else raise."""
    if isinstance(operand, bool) or not isinstance(operand, int):
        raise ValueError("operand must be an integer")
    if operand < 0:
        raise ValueError(f"operand index must not be negative: {operand!r}")
    return operand


def _require_kind(kind: str) -> str:
    """Return ``kind`` if it is a non-empty, non-blank string, else raise."""
    if not isinstance(kind, str):
        raise ValueError(f"type must be a string, got {type(kind).__name__}")
    stripped = kind.strip()
    if not stripped:
        raise ValueError("operand type must not be empty")
    return stripped


class SetOpTypeUseCase:
    """Resolve a selector and set the display type of one of its operands."""

    def __init__(
        self, operands: OperandGateway, database: DatabaseGateway
    ) -> None:
        self._operands = operands
        self._database = database

    def execute(self, command: SetOpTypeCommand) -> SetOpTypeResult:
        """Resolve ``command.address`` and set operand ``command.operand``'s type.

        The operand index and display kind are validated, the selector is resolved
        against the database gateway, then the operand gateway applies the
        representation and reports the label in force afterward. The completed
        change is wrapped as an
        :class:`~idamesh.domain.entities.operand_type.OperandTypeSetting`. An
        out-of-range operand, an unknown kind, or an unresolvable address surfaces
        as an error the interface layer renders as an ``isError`` result.
        """
        operand = _require_operand(command.operand)
        kind = _require_kind(command.type)
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        applied = self._operands.set_op_type(ea, operand, kind)
        setting = OperandTypeSetting(address=ea, operand=operand, type=applied)
        return SetOpTypeResult(setting=setting)
