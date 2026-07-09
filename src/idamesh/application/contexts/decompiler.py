"""The decompile use-case."""

from __future__ import annotations

from idamesh.application.dto.decompiler import DecompileCommand, DecompileResult
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.decompiler import DecompilerGateway
from idamesh.domain.values.address import Selector


class DecompileUseCase:
    """Resolve a selector to a function and return its pseudocode.

    Uses the database gateway to resolve the polymorphic ``address`` selector,
    then the decompiler gateway to produce pseudocode.
    """

    def __init__(
        self,
        decompiler: DecompilerGateway,
        database: DatabaseGateway,
    ) -> None:
        self._decompiler = decompiler
        self._database = database

    def execute(self, command: DecompileCommand) -> DecompileResult:
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        pseudocode = self._decompiler.decompile(ea)
        return DecompileResult(pseudocode=pseudocode)
