"""Command/Result DTOs for the ``set_op_type`` tool.

``SetOpTypeCommand`` carries a polymorphic address selector, the zero-based
``operand`` index, and the display ``type`` (kind) to apply; ``SetOpTypeResult``
wraps the resulting
:class:`~idamesh.domain.entities.operand_type.OperandTypeSetting`. The selector is
resolved in the use-case, which then routes the change through the operand gateway.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.operand_type import OperandTypeSetting


@dataclass(frozen=True)
class SetOpTypeCommand:
    """Input for ``set_op_type``.

    ``address`` is a polymorphic selector resolved to the instruction; ``operand``
    is the zero-based operand index; ``type`` names the display representation to
    apply (e.g. ``"hex"``, ``"dec"``, ``"char"``, ``"offset"``).
    """

    address: str
    operand: int
    type: str


@dataclass(frozen=True)
class SetOpTypeResult:
    """Output for ``set_op_type`` — the completed operand-type change."""

    setting: OperandTypeSetting
