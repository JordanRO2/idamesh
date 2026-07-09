"""Catalog registration and wire-shape projection for ``define_code`` (mutating).

The ``DefineCodeView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`define_code_view` renders the completed creation into that
flat shape (address as ``0x`` hex, ``ok`` always true on success). The tool is
marked ``@registry.mutating`` so its advertised ``readOnlyHint`` is ``false``. The
field names mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.define_code import DefineCodeUseCase
from idamesh.application.dto.define_code import DefineCodeCommand
from idamesh.domain.entities.instruction_definition import InstructionDefinition
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class DefineCodeView(TypedDict):
    """The outcome of one ``define_code`` call."""

    address: str
    ok: bool
    size: int


def define_code_view(definition: InstructionDefinition) -> DefineCodeView:
    """Project an :class:`InstructionDefinition` into its wire shape."""
    return DefineCodeView(
        address=definition.address.hex(),
        ok=True,
        size=definition.size,
    )


def register_define_code(
    registry: Registry,
    *,
    define_code_use_case: DefineCodeUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``define_code`` against the define-code use-case (a mutating tool)."""

    @registry.tool(name="define_code")
    @registry.mutating
    def define_code(address: str) -> DefineCodeView:
        """Create an instruction at ``address``. The ``address`` may be a
        hexadecimal literal (``0x…``), a decimal literal, or a symbol name; it is
        resolved first and should point at the first byte of the intended
        instruction. The analyzer decodes one instruction and infers its length.
        The result reports the resolved ``address`` (``0x`` hex), ``ok``, and the
        ``size`` in bytes the new instruction occupies. This modifies the database.
        Bytes that do not decode into a valid instruction, or an unresolvable
        address, yields an error result rather than failing the protocol request."""
        command = DefineCodeCommand(address=address)
        result = run_mutation(
            executor, lambda: define_code_use_case.execute(command)
        )
        return define_code_view(result.definition)
