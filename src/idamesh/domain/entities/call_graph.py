"""The call-graph value objects — a bounded call graph rooted at one function.

A :class:`CallGraph` is the breadth-first exploration of the "who calls whom"
relation starting from a :attr:`root` function: :class:`CallGraphNode`\\ s are the
functions reached, and :class:`CallGraphEdge`\\ s are the directed call edges
between them (``source`` calls ``target``). The node/edge decomposition and the
``root`` + ``truncated`` framing are the interoperability contract a client reads
to draw the graph; the bounded, deterministic traversal that produces them is our
design and lives in :mod:`idamesh.domain.services.call_graph`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class CallGraphNode:
    """One function reached during the traversal: its entry ``address`` and name."""

    address: Address
    name: Optional[str] = None


@dataclass(frozen=True)
class CallGraphEdge:
    """A directed call edge — the function at ``source`` calls the one at ``target``."""

    source: Address
    target: Address


@dataclass(frozen=True)
class CallGraph:
    """A bounded call graph explored breadth-first from ``root``."""

    root: Address
    nodes: Tuple[CallGraphNode, ...] = ()
    edges: Tuple[CallGraphEdge, ...] = ()
    truncated: bool = False
