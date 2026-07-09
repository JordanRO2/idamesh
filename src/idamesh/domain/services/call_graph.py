"""The call-graph traversal service — a pure, IDA-free breadth-first explorer.

:class:`CallGraphService` builds a :class:`~idamesh.domain.entities.call_graph.CallGraph`
by walking the callee relation transitively from a root, one depth layer at a
time, over any :class:`~idamesh.domain.ports.xrefs.XrefRepository`. Keeping the
traversal here — a stateless domain service that takes the repository as an
argument — makes it unit-testable against a fake repository with no IDA present,
and keeps the bound knobs (depth, node ceiling) and ``truncated`` reporting in one
reviewable place. The whole design (bounded, deterministic BFS) is ours.
"""

from __future__ import annotations

from collections import deque
from typing import Deque, Dict, List, Set, Tuple

from idamesh.domain.entities.call_graph import CallGraph, CallGraphEdge, CallGraphNode
from idamesh.domain.ports.xrefs import XrefRepository
from idamesh.domain.values.address import Address

#: Domain-local ceiling on distinct nodes a traversal materializes before it
#: stops early and flags the graph ``truncated``. The application layer may pass
#: a tighter cap; this guards a caller that passes none.
DEFAULT_MAX_NODES: int = 1000


class CallGraphService:
    """Build a bounded call graph by breadth-first traversal of callee edges."""

    def build(
        self,
        root: Address,
        xrefs: XrefRepository,
        *,
        depth: int,
        max_nodes: int = DEFAULT_MAX_NODES,
    ) -> CallGraph:
        """Explore the callee relation breadth-first from ``root``.

        Starting at ``root``, each newly discovered function's direct callees
        (via :meth:`XrefRepository.callees`) are expanded layer by layer until
        ``depth`` layers have been explored or ``max_nodes`` distinct functions
        have been collected. Every distinct function becomes a
        :class:`~idamesh.domain.entities.call_graph.CallGraphNode` and every call
        relation a :class:`~idamesh.domain.entities.call_graph.CallGraphEdge`;
        cycles are visited once. The returned graph's ``truncated`` flag is set
        when the depth or node bound elided further expansion.
        """
        layers = depth if depth > 0 else 0

        # Distinct nodes keyed by EA, preserving first-seen order. The root is
        # always present even when nothing is expanded; its name is unknown here
        # (callee edges name their *target*), so it starts unnamed and is filled
        # in only if a cycle later reaches it as someone's callee.
        nodes: Dict[int, CallGraphNode] = {root.value: CallGraphNode(address=root)}
        edges: List[CallGraphEdge] = []
        edge_seen: Set[Tuple[int, int]] = set()
        # Nodes ever queued for a callee walk — guards against re-walking a
        # function reached along two paths and against infinite cycles.
        scheduled: Set[int] = {root.value}
        truncated = False

        queue: Deque[Tuple[Address, int]] = deque([(root, 0)])
        while queue:
            current, level = queue.popleft()
            try:
                children = xrefs.callees(current)
            except (LookupError, RuntimeError):
                # The root must resolve to a real function; an out-of-function
                # root is a caller error the interface surfaces as ``isError``,
                # so it propagates. A *discovered* callee target that is not
                # itself a function body — an import, a jump/tail-call thunk, or
                # an unanalyzed address the callee walk cannot enumerate — is a
                # leaf of the call graph. Treat it as such rather than letting a
                # single unexpandable frontier node abort the whole traversal.
                if current.value == root.value:
                    raise
                continue
            if level >= layers:
                # Frontier function at the depth bound: not expanded. If it has
                # any callees, the bound elided them, so the graph is partial.
                if children:
                    truncated = True
                continue
            for edge in children:
                target = edge.target
                existing = nodes.get(target.value)
                if existing is None:
                    if len(nodes) >= max_nodes:
                        # Node ceiling reached: drop this function and the edge
                        # into it so the graph stays internally consistent.
                        truncated = True
                        continue
                    nodes[target.value] = CallGraphNode(
                        address=target, name=edge.target_name
                    )
                elif existing.name is None and edge.target_name is not None:
                    # Backfill a name we lacked (e.g. the root seen via a cycle).
                    nodes[target.value] = CallGraphNode(
                        address=target, name=edge.target_name
                    )
                pair = (current.value, target.value)
                if pair not in edge_seen:
                    edge_seen.add(pair)
                    edges.append(CallGraphEdge(source=current, target=target))
                if target.value not in scheduled:
                    scheduled.add(target.value)
                    queue.append((target, level + 1))

        return CallGraph(
            root=root,
            nodes=tuple(nodes.values()),
            edges=tuple(edges),
            truncated=truncated,
        )
