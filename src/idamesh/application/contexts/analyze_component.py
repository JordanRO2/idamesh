"""The ``analyze_component`` use-case — analyze a call subtree as one unit.

Resolves the polymorphic ``address`` selector to the root function, clamps the
requested traversal ``depth``, and hands the root plus the shared cross-reference
and function repositories to the pure
:class:`~idamesh.domain.services.component.ComponentService`, which explores the
bounded call subtree and rolls its members up into a
:class:`~idamesh.domain.entities.component.Component`. The application layer owns
only selector resolution and the depth/node bounds; the aggregation is the domain
service's.
"""

from __future__ import annotations

from idamesh.application.dto.analyze_component import (
    COMPONENT_MAX_NODES,
    DEFAULT_COMPONENT_DEPTH,
    MAX_COMPONENT_DEPTH,
    AnalyzeComponentCommand,
    AnalyzeComponentResult,
)
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.functions import FunctionRepository
from idamesh.domain.ports.xrefs import XrefRepository
from idamesh.domain.services.component import ComponentService
from idamesh.domain.values.address import Selector


class AnalyzeComponentUseCase:
    """Resolve a root selector and aggregate its bounded call subtree."""

    def __init__(
        self,
        database: DatabaseGateway,
        functions: FunctionRepository,
        xrefs: XrefRepository,
        component: ComponentService,
    ) -> None:
        self._database = database
        self._functions = functions
        self._xrefs = xrefs
        self._component = component

    def execute(self, command: AnalyzeComponentCommand) -> AnalyzeComponentResult:
        """Resolve ``command.address`` and roll up its call subtree.

        The selector is parsed and resolved against the database gateway; the
        depth is clamped to :data:`MAX_COMPONENT_DEPTH`. An out-of-range,
        unresolvable, or out-of-function root surfaces as the underlying error,
        which the interface layer renders as an ``isError`` result.
        """
        selector = Selector.parse(command.address)
        root = self._database.resolve(selector)
        depth = self._clamp_depth(command.depth)
        component = self._component.assemble(
            root,
            self._xrefs,
            self._functions,
            depth=depth,
            max_nodes=COMPONENT_MAX_NODES,
        )
        return AnalyzeComponentResult(component=component)

    @staticmethod
    def _clamp_depth(depth: int) -> int:
        try:
            value = int(depth)
        except (TypeError, ValueError):
            return DEFAULT_COMPONENT_DEPTH
        if value < 0:
            return 0
        if value > MAX_COMPONENT_DEPTH:
            return MAX_COMPONENT_DEPTH
        return value
