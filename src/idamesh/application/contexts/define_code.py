"""The ``define_code`` use-case: create an instruction at a resolved address.

Resolves the polymorphic selector against the database gateway (mirroring the read
tools), then routes the creation through the
:class:`~idamesh.domain.ports.instruction.InstructionGateway`, which decodes one
instruction and reports its length. Decoding and instruction creation are the
gateway's SDK-level job; the selector resolution and result assembly are the
application's.
"""

from __future__ import annotations

from idamesh.application.dto.define_code import (
    DefineCodeCommand,
    DefineCodeResult,
)
from idamesh.domain.entities.instruction_definition import InstructionDefinition
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.instruction import InstructionGateway
from idamesh.domain.values.address import Selector


class DefineCodeUseCase:
    """Resolve a selector and create an instruction at the address there."""

    def __init__(
        self, instructions: InstructionGateway, database: DatabaseGateway
    ) -> None:
        self._instructions = instructions
        self._database = database

    def execute(self, command: DefineCodeCommand) -> DefineCodeResult:
        """Resolve ``command.address`` and create an instruction at it.

        The selector is resolved against the database gateway, then the instruction
        gateway decodes one instruction and reports its byte length. The completed
        creation is wrapped as an
        :class:`~idamesh.domain.entities.instruction_definition.InstructionDefinition`.
        Bytes that do not decode, or an unresolvable address, surface as an error
        the interface layer renders as an ``isError`` result.
        """
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        size = self._instructions.define_code(ea)
        definition = InstructionDefinition(address=ea, size=size)
        return DefineCodeResult(definition=definition)
