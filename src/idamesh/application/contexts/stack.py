"""The ``declare_stack`` and ``delete_stack`` use-cases: edit a function's frame.

Both resolve the polymorphic ``function`` selector against the database gateway
(mirroring the read tools) and then route the change through the shared
:class:`~idamesh.domain.ports.stack.StackGateway`. ``declare_stack`` defines a typed
frame variable at an offset; ``delete_stack`` removes one by name. A declaration the
frame refuses, a name the frame does not carry, or an unresolvable function
surfaces as an error the interface layer renders as an ``isError`` result.
"""

from __future__ import annotations

from idamesh.application.dto.stack import (
    DeclareStackCommand,
    DeclareStackResult,
    DeleteStackCommand,
    DeleteStackResult,
)
from idamesh.domain.entities.stack_variable import (
    StackVariableDefinition,
    StackVariableDeletion,
)
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.stack import StackGateway
from idamesh.domain.values.address import Selector


def _require_name(name: str) -> str:
    """Return ``name`` if it is a non-empty, non-blank string, else raise."""
    if not isinstance(name, str):
        raise ValueError(f"name must be a string, got {type(name).__name__}")
    stripped = name.strip()
    if not stripped:
        raise ValueError("variable name must not be empty")
    return stripped


def _require_type(declaration: str) -> str:
    """Return ``declaration`` if it is a non-empty, non-blank string, else raise."""
    if not isinstance(declaration, str):
        raise ValueError(
            f"type must be a string, got {type(declaration).__name__}"
        )
    stripped = declaration.strip()
    if not stripped:
        raise ValueError("variable type must not be empty")
    return stripped


class DeclareStackUseCase:
    """Resolve a function selector and define a frame variable on it."""

    def __init__(self, stack: StackGateway, database: DatabaseGateway) -> None:
        self._stack = stack
        self._database = database

    def execute(self, command: DeclareStackCommand) -> DeclareStackResult:
        """Resolve ``command.function`` and define the requested frame variable.

        The variable name and type are validated, the function selector is resolved
        against the database gateway, then the stack gateway places the typed
        variable at ``command.offset``. The completed definition is wrapped as a
        :class:`~idamesh.domain.entities.stack_variable.StackVariableDefinition`. A
        refused declaration or an unresolvable function surfaces as an error the
        interface layer renders as an ``isError`` result.
        """
        name = _require_name(command.name)
        type = _require_type(command.type)
        selector = Selector.parse(command.function)
        func = self._database.resolve(selector)
        self._stack.declare(func, name, type, command.offset)
        definition = StackVariableDefinition(function=func, name=name)
        return DeclareStackResult(definition=definition)


class DeleteStackUseCase:
    """Resolve a function selector and remove a frame variable by name."""

    def __init__(self, stack: StackGateway, database: DatabaseGateway) -> None:
        self._stack = stack
        self._database = database

    def execute(self, command: DeleteStackCommand) -> DeleteStackResult:
        """Resolve ``command.function`` and remove the named frame variable.

        The variable name is validated, the function selector is resolved against
        the database gateway, then the stack gateway removes the variable. The
        completed removal is wrapped as a
        :class:`~idamesh.domain.entities.stack_variable.StackVariableDeletion`. A
        name the frame does not carry or an unresolvable function surfaces as an
        error the interface layer renders as an ``isError`` result.
        """
        name = _require_name(command.name)
        selector = Selector.parse(command.function)
        func = self._database.resolve(selector)
        self._stack.delete(func, name)
        deletion = StackVariableDeletion(function=func, name=name)
        return DeleteStackResult(deletion=deletion)
