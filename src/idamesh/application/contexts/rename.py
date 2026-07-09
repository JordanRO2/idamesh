"""The ``rename`` use-case: set the user name at a resolved address.

Resolves the polymorphic selector against the database gateway (mirroring the read
tools), validates the requested name, then writes it through the
:class:`~idamesh.domain.ports.naming.NamingGateway`, which returns the prior name.
Name validation is kept *pure* here in the application layer: an empty or
whitespace-only name is rejected before the gateway is touched, so an obviously
bad request fails without a database round-trip; the gateway still enforces the
SDK-level identifier and collision rules that only it can see.
"""

from __future__ import annotations

from idamesh.application.dto.rename import RenameCommand, RenameResult
from idamesh.domain.entities.rename import Renaming
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.naming import NamingGateway
from idamesh.domain.values.address import Selector


def _require_name(name: str) -> str:
    """Return ``name`` if it is a non-empty, non-blank string, else raise.

    An empty name is not a rename — in the SDK it *clears* the user name — so it is
    refused here to keep ``rename`` a pure set operation. Leading/trailing
    whitespace is stripped; a name that is blank once stripped is rejected.
    """
    if not isinstance(name, str):
        raise ValueError(f"name must be a string, got {type(name).__name__}")
    stripped = name.strip()
    if not stripped:
        raise ValueError("name must not be empty")
    return stripped


class RenameUseCase:
    """Resolve a selector and install a user name on the item there."""

    def __init__(self, naming: NamingGateway, database: DatabaseGateway) -> None:
        self._naming = naming
        self._database = database

    def execute(self, command: RenameCommand) -> RenameResult:
        """Resolve ``command.address`` and set its name to ``command.name``.

        The selector is parsed and resolved against the database gateway; the new
        name is validated, then the naming gateway installs it and reports the name
        previously in force. The completed change is wrapped as a
        :class:`~idamesh.domain.entities.rename.Renaming`. An invalid or clashing
        name, or an unresolvable address, surfaces as an error the interface layer
        renders as an ``isError`` result.
        """
        name = _require_name(command.name)
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        old_name = self._naming.set_name(ea, name)
        renaming = Renaming(address=ea, old_name=old_name, name=name)
        return RenameResult(renaming=renaming)
