"""Command/Result DTOs for ``callgraph``.

The command carries the polymorphic ``address`` selector (resolved to the root
function) and a bounded ``depth``; the result wraps the built
:class:`~idamesh.domain.entities.call_graph.CallGraph`. Depth is clamped to a
server maximum so an unbounded request cannot fan the traversal out without limit.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.call_graph import CallGraph

#: Traversal depth used when a client omits ``depth``.
DEFAULT_CALLGRAPH_DEPTH: int = 3
#: Hard ceiling a requested ``depth`` is clamped to before traversal.
MAX_CALLGRAPH_DEPTH: int = 12
#: Ceiling on distinct nodes the traversal materializes before flagging
#: ``truncated``; passed through to the domain call-graph service.
MAX_CALLGRAPH_NODES: int = 1000


@dataclass(frozen=True)
class CallgraphCommand:
    """Input for ``callgraph``.

    ``address`` is a polymorphic selector — a hex literal (``0x…``), a decimal
    literal, or a symbol name — resolved to the root function. ``depth`` bounds
    how many call layers are explored and is clamped to a server maximum.
    """

    address: str
    depth: int = DEFAULT_CALLGRAPH_DEPTH


@dataclass(frozen=True)
class CallgraphResult:
    """Output for ``callgraph`` — the bounded call graph rooted at the selector."""

    graph: CallGraph
