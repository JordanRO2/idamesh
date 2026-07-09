"""Command/Result DTOs for the ``define_code`` tool.

``DefineCodeCommand`` carries a polymorphic address selector; ``DefineCodeResult``
wraps the resulting
:class:`~idamesh.domain.entities.instruction_definition.InstructionDefinition`. The
selector is resolved in the use-case, which then routes the creation through the
instruction gateway.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.instruction_definition import InstructionDefinition


@dataclass(frozen=True)
class DefineCodeCommand:
    """Input for ``define_code`` — the selector for the instruction's address."""

    address: str


@dataclass(frozen=True)
class DefineCodeResult:
    """Output for ``define_code`` — the completed instruction creation."""

    definition: InstructionDefinition
