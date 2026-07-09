"""The ``set_type`` use-case: apply a C declaration at a resolved address.

Resolves the polymorphic selector against the database gateway (mirroring the read
tools), validates that a non-empty declaration was supplied, then hands the parse
-and-apply to the
:class:`~idamesh.domain.ports.type_mutation.TypeMutationGateway`, which returns the
retyped item's name. Parsing the declaration and applying the type are the
gateway's SDK-level job; the empty-input guard and the result assembly are the
application's.
"""

from __future__ import annotations

from idamesh.application.dto.set_type import SetTypeCommand, SetTypeResult
from idamesh.domain.entities.type_application import TypeApplication
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.type_mutation import TypeMutationGateway
from idamesh.domain.values.address import Selector


def _require_decl(decl: str) -> str:
    """Return ``decl`` if it is a non-empty, non-blank string, else raise."""
    if not isinstance(decl, str):
        raise ValueError(f"type must be a string, got {type(decl).__name__}")
    stripped = decl.strip()
    if not stripped:
        raise ValueError("type declaration must not be empty")
    return stripped


class SetTypeUseCase:
    """Resolve a selector and apply a parsed C type to the item there."""

    def __init__(
        self, types: TypeMutationGateway, database: DatabaseGateway
    ) -> None:
        self._types = types
        self._database = database

    def execute(self, command: SetTypeCommand) -> SetTypeResult:
        """Resolve ``command.address`` and apply ``command.type`` at it.

        The selector is parsed and resolved against the database gateway; the
        declaration is checked non-empty, then the type-mutation gateway parses it
        and applies the resulting type, reporting the item's name afterward. The
        completed application is wrapped as a
        :class:`~idamesh.domain.entities.type_application.TypeApplication`. An
        unparseable declaration, a type that cannot be applied at the address, or
        an unresolvable address surfaces as an error the interface layer renders as
        an ``isError`` result.
        """
        decl = _require_decl(command.type)
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        applied_name = self._types.apply_type(ea, decl)
        application = TypeApplication(address=ea, name=applied_name, type=decl)
        return SetTypeResult(application=application)
