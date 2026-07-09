"""The ``make_data`` use-case: define a data item at a resolved address.

Resolves the polymorphic selector against the database gateway (mirroring the read
tools), validates that either a C type or a positive size was supplied, then hands
the definition to the
:class:`~idamesh.domain.ports.data_definition.DataDefinitionGateway`, which returns
the type actually applied and the item's size. Parsing the declaration, creating
the item, and applying the type are the gateway's SDK-level job; the "need a type
or a size" guard and the result assembly are the application's.
"""

from __future__ import annotations

from idamesh.application.dto.make_data import MakeDataCommand, MakeDataResult
from idamesh.domain.entities.data_definition import DataDefinition
from idamesh.domain.ports.data_definition import DataDefinitionGateway
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.values.address import Selector


def _normalize(type: str, size: int) -> tuple[str, int]:
    """Validate the type/size pair, returning the stripped type and size.

    At least one of a non-blank ``type`` declaration or a positive ``size`` must be
    given; a request with neither is not a definition and is refused before the
    gateway is touched. A negative size is rejected outright.
    """
    if not isinstance(type, str):
        raise ValueError("type must be a string")
    if not isinstance(size, int) or isinstance(size, bool):
        raise ValueError("size must be an integer")
    if size < 0:
        raise ValueError(f"size must not be negative: {size!r}")
    decl = type.strip()
    if not decl and size == 0:
        raise ValueError("make_data requires a type declaration or a positive size")
    return decl, size


class MakeDataUseCase:
    """Resolve a selector and define a data item at the item there."""

    def __init__(
        self, data: DataDefinitionGateway, database: DatabaseGateway
    ) -> None:
        self._data = data
        self._database = database

    def execute(self, command: MakeDataCommand) -> MakeDataResult:
        """Resolve ``command.address`` and define a data item at it.

        The type/size pair is validated, the selector is resolved against the
        database gateway, then the data-definition gateway creates the item —
        applying the C type when one is given, else a primitive of the requested
        size — and reports the type in force and the item's byte span afterward. The
        completed definition is wrapped as a
        :class:`~idamesh.domain.entities.data_definition.DataDefinition`. An
        unparseable declaration, an unsupported size, or an unresolvable address
        surfaces as an error the interface layer renders as an ``isError`` result.
        """
        decl, size = _normalize(command.type, command.size)
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        applied_type, applied_size = self._data.make_data(ea, decl, size)
        definition = DataDefinition(
            address=ea, type=applied_type, size=applied_size
        )
        return MakeDataResult(definition=definition)
