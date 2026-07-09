"""The ``callgraph`` use-case.

Resolves the polymorphic ``address`` selector against the database gateway
(mirroring ``decompile`` / ``callees``), clamps the requested depth to a server
maximum, then delegates to the pure
:class:`~idamesh.domain.services.call_graph.CallGraphService` to traverse the
callee relation over the shared cross-reference repository.
"""

from __future__ import annotations

from idamesh.application.dto.call_graph import (
    MAX_CALLGRAPH_DEPTH,
    MAX_CALLGRAPH_NODES,
    CallgraphCommand,
    CallgraphResult,
)
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.xrefs import XrefRepository
from idamesh.domain.services.call_graph import CallGraphService
from idamesh.domain.values.address import Selector


class CallgraphUseCase:
    """Resolve a selector and build the bounded call graph rooted at it."""

    def __init__(self, xrefs: XrefRepository, database: DatabaseGateway) -> None:
        self._xrefs = xrefs
        self._database = database
        self._service = CallGraphService()

    def execute(self, command: CallgraphCommand) -> CallgraphResult:
        """Resolve ``command.address`` and traverse its call graph.

        The selector is parsed and resolved to the root function; ``depth`` is
        clamped to :data:`MAX_CALLGRAPH_DEPTH` (and floored at zero), and the
        traversal is bounded at :data:`MAX_CALLGRAPH_NODES`. An out-of-range or
        unresolvable address surfaces as the gateway's error, which the interface
        layer renders as an ``isError`` result.
        """
        selector = Selector.parse(command.address)
        root = self._database.resolve(selector)
        depth = command.depth
        if depth < 0:
            depth = 0
        elif depth > MAX_CALLGRAPH_DEPTH:
            depth = MAX_CALLGRAPH_DEPTH
        graph = self._service.build(
            root, self._xrefs, depth=depth, max_nodes=MAX_CALLGRAPH_NODES
        )
        return CallgraphResult(graph=graph)
