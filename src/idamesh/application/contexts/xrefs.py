"""The ``xrefs_to`` and ``callees`` use-cases.

Both resolve the polymorphic ``address`` selector against the database gateway
(mirroring ``decompile``), then query the shared cross-reference repository:
``xrefs_to`` for the edges pointing at the resolved address, ``callees`` for the
call edges leaving the function that owns it.
"""

from __future__ import annotations

from idamesh.application.dto.xrefs import (
    CALLEES_LIMIT,
    XREFS_TO_LIMIT,
    CalleesCommand,
    CalleesResult,
    XrefsToCommand,
    XrefsToResult,
)
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.xrefs import XrefRepository
from idamesh.domain.values.address import Selector


class XrefsToUseCase:
    """Resolve a selector and return the cross-references pointing at it."""

    def __init__(self, xrefs: XrefRepository, database: DatabaseGateway) -> None:
        self._xrefs = xrefs
        self._database = database

    def execute(self, command: XrefsToCommand) -> XrefsToResult:
        """Resolve ``command.address`` and collect the edges targeting it.

        The selector is parsed and resolved against the database gateway (as
        ``decompile`` does); the repository then supplies every inbound edge.
        The reply is capped at :data:`XREFS_TO_LIMIT`, with ``truncated`` set
        when the cap elided edges.
        """
        selector = Selector.parse(command.address)
        target = self._database.resolve(selector)
        edges = self._xrefs.refs_to(target)
        kept = tuple(edges[:XREFS_TO_LIMIT])
        return XrefsToResult(
            target=target,
            xrefs=kept,
            truncated=len(edges) > XREFS_TO_LIMIT,
        )


class CalleesUseCase:
    """Resolve a selector and return the direct callees of its function."""

    def __init__(self, xrefs: XrefRepository, database: DatabaseGateway) -> None:
        self._xrefs = xrefs
        self._database = database

    def execute(self, command: CalleesCommand) -> CalleesResult:
        """Resolve ``command.address`` and collect its function's call edges.

        The selector is resolved to a concrete address; the repository walks the
        owning function and returns its distinct call edges. The reply is capped
        at :data:`CALLEES_LIMIT`, with ``truncated`` set when the cap elided
        callees. An address inside no function surfaces as the repository's
        error, which the interface layer renders as an ``isError`` result.
        """
        selector = Selector.parse(command.address)
        func = self._database.resolve(selector)
        edges = self._xrefs.callees(func)
        kept = tuple(edges[:CALLEES_LIMIT])
        return CalleesResult(
            func=func,
            callees=kept,
            truncated=len(edges) > CALLEES_LIMIT,
        )
