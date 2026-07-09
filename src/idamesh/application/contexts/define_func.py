"""The ``define_func`` and ``undefine`` use-cases: create/revert an item.

Both resolve the polymorphic selector against the database gateway (mirroring the
read tools) and then route the change through the shared
:class:`~idamesh.domain.ports.code_definition.CodeDefinitionGateway`.
``define_func`` promotes the code at the address into a function and reports its
name; ``undefine`` reverts the item there back to raw bytes. A create the analyzer
refuses, an address with nothing to undefine, or an unresolvable address surfaces
as an error the interface layer renders as an ``isError`` result.
"""

from __future__ import annotations

from idamesh.application.dto.define_func import (
    DefineFuncCommand,
    DefineFuncResult,
    UndefineCommand,
    UndefineResult,
)
from idamesh.domain.entities.code_definition import (
    FunctionDefinition,
    Undefinition,
)
from idamesh.domain.ports.code_definition import CodeDefinitionGateway
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.values.address import Selector


class DefineFuncUseCase:
    """Resolve a selector and create a function at the address there."""

    def __init__(
        self, code: CodeDefinitionGateway, database: DatabaseGateway
    ) -> None:
        self._code = code
        self._database = database

    def execute(self, command: DefineFuncCommand) -> DefineFuncResult:
        """Resolve ``command.address`` and create a function at it.

        The selector is resolved against the database gateway, then the
        code-definition gateway creates the function (the analyzer inferring its
        end) and reports its name. The completed creation is wrapped as a
        :class:`~idamesh.domain.entities.code_definition.FunctionDefinition`. A
        function that cannot be created there, or an unresolvable address, surfaces
        as an error the interface layer renders as an ``isError`` result.
        """
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        name = self._code.define_func(ea)
        definition = FunctionDefinition(address=ea, name=name)
        return DefineFuncResult(definition=definition)


class UndefineUseCase:
    """Resolve a selector and undefine the item at the address there."""

    def __init__(
        self, code: CodeDefinitionGateway, database: DatabaseGateway
    ) -> None:
        self._code = code
        self._database = database

    def execute(self, command: UndefineCommand) -> UndefineResult:
        """Resolve ``command.address`` and undefine the item at it.

        The selector is resolved against the database gateway, then the
        code-definition gateway reverts the function, code, or data covering the
        address back to raw bytes. The completed change is wrapped as an
        :class:`~idamesh.domain.entities.code_definition.Undefinition`. An address
        with nothing to undefine, or an unresolvable address, surfaces as an error
        the interface layer renders as an ``isError`` result.
        """
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        self._code.undefine(ea)
        undefinition = Undefinition(address=ea)
        return UndefineResult(undefinition=undefinition)
