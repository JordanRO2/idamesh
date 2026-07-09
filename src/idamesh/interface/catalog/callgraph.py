"""Catalog registration and wire-shape projection for ``callgraph``.

The ``CallGraphNodeView`` / ``CallGraphEdgeView`` / ``CallgraphView``
``TypedDict``s give the schema compiler an object-rooted ``outputSchema``;
:func:`callgraph_view` renders the traversed graph into that flat shape
(addresses as ``0x`` hex). The ``from`` key on an edge collides with the Python
keyword, so it needs the functional ``TypedDict`` spelling. The field names
mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.call_graph import CallgraphUseCase
from idamesh.application.dto.call_graph import (
    DEFAULT_CALLGRAPH_DEPTH,
    CallgraphCommand,
    CallgraphResult,
)
from idamesh.domain.entities.call_graph import CallGraphEdge, CallGraphNode
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class CallGraphNodeView(TypedDict):
    """One function node in a ``callgraph`` result."""

    address: str
    name: Optional[str]


#: One directed call edge. ``from`` collides with the Python keyword, so the
#: functional ``TypedDict`` form is required.
CallGraphEdgeView = TypedDict(
    "CallGraphEdgeView",
    {
        "from": str,
        "to": str,
    },
)


class CallgraphView(TypedDict):
    """A bounded call graph rooted at ``root``."""

    root: str
    nodes: List[CallGraphNodeView]
    edges: List[CallGraphEdgeView]
    truncated: bool


def call_graph_node_view(node: CallGraphNode) -> CallGraphNodeView:
    """Project one graph node into its wire shape."""
    return CallGraphNodeView(address=node.address.hex(), name=node.name)


def call_graph_edge_view(edge: CallGraphEdge) -> CallGraphEdgeView:
    """Project one call edge into its wire shape."""
    return {"from": edge.source.hex(), "to": edge.target.hex()}


def callgraph_view(result: CallgraphResult) -> CallgraphView:
    """Project a ``callgraph`` result into its wire shape."""
    graph = result.graph
    return CallgraphView(
        root=graph.root.hex(),
        nodes=[call_graph_node_view(node) for node in graph.nodes],
        edges=[call_graph_edge_view(edge) for edge in graph.edges],
        truncated=graph.truncated,
    )


def register_callgraph(
    registry: Registry,
    *,
    callgraph_use_case: CallgraphUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``callgraph`` against the bounded-traversal use-case."""

    @registry.tool(name="callgraph")
    def callgraph(
        address: str, depth: int = DEFAULT_CALLGRAPH_DEPTH
    ) -> CallgraphView:
        """Return the call graph rooted at the function at or containing
        ``address``, explored breadth-first. The ``address`` may be a
        hexadecimal literal (``0x…``), a decimal literal, or a symbol name; it is
        resolved and mapped to its owning function first. ``depth`` bounds how
        many call layers are explored and is clamped to a server maximum. The
        result reports the ``root`` address, the ``nodes`` reached (each with its
        ``address`` and ``name``), the ``from``/``to`` call ``edges`` between
        them, and a ``truncated`` flag set when a bound elided further
        exploration. An out-of-range, unresolvable, or out-of-function address
        yields an error result rather than failing the protocol request."""
        command = CallgraphCommand(address=address, depth=depth)
        result = run_use_case(
            executor, lambda: callgraph_use_case.execute(command)
        )
        return callgraph_view(result)
