"""The component aggregation service — a pure roll-up over a call subtree.

:class:`ComponentService` turns the bounded call-subtree rooted at a function into
a :class:`~idamesh.domain.entities.component.Component`: it delegates the
breadth-first exploration to :class:`~idamesh.domain.services.call_graph.CallGraphService`,
then, for each discovered member, reads its size from the function repository and
its caller/callee degree from the cross-reference repository, and rolls the whole
set up into aggregate stats — member count, total byte size, and the split of
call edges that stay inside the component versus leave it. Like ``CallGraphService``
it takes the repositories as call arguments, so the roll-up is a pure, IDA-free
policy that a fake repository can drive in a unit test. The clustering view and the
internal/external edge split are our design.
"""

from __future__ import annotations

from idamesh.domain.entities.component import Component, ComponentMember
from idamesh.domain.ports.functions import FunctionRepository
from idamesh.domain.ports.xrefs import XrefRepository
from idamesh.domain.services.call_graph import DEFAULT_MAX_NODES, CallGraphService
from idamesh.domain.values.address import Address


class ComponentService:
    """Aggregate a bounded call subtree into a component roll-up."""

    def __init__(self, call_graph: CallGraphService | None = None) -> None:
        self._call_graph = call_graph or CallGraphService()

    def assemble(
        self,
        root: Address,
        xrefs: XrefRepository,
        functions: FunctionRepository,
        *,
        depth: int,
        max_nodes: int = DEFAULT_MAX_NODES,
    ) -> Component:
        """Explore the subtree at ``root`` and roll its members up.

        The call graph is built first (bounded by ``depth`` and ``max_nodes``).
        A materialised node is a *member* when it is the root or resolves to a
        real function body; discovered leaves that do not (an import slot or a
        tail-call thunk target) are excluded from the membership but still counted
        against it. For each member the size comes from ``functions`` and the
        inbound/outbound degree from ``xrefs``; each outbound call edge is tallied
        as *internal* when its target is another member and *external* otherwise
        (a call into an import, a thunk, or a function past the depth or node
        bound). An out-of-function ``root`` propagates the repository error, which
        the interface layer renders as ``isError``.
        """
        graph = self._call_graph.build(
            root, xrefs, depth=depth, max_nodes=max_nodes
        )

        # A node is an internal member when it is the root or resolves to a real
        # function body; import/thunk leaves reached as callees are not.
        node_funcs = {node.address.value: functions.get(node.address) for node in graph.nodes}
        member_eas = {
            node.address.value
            for node in graph.nodes
            if node.address.value == root.value
            or node_funcs[node.address.value] is not None
        }

        members: list[ComponentMember] = []
        total_size = 0
        internal_calls = 0
        external_calls = 0

        for node in graph.nodes:
            if node.address.value not in member_eas:
                continue
            func = node_funcs[node.address.value]
            size = func.size if func is not None else 0
            name = node.name if node.name is not None else (
                func.name if func is not None else None
            )

            callees = self._safe_callees(xrefs, node.address)
            callers = self._safe_refs_to(xrefs, node.address)
            for edge in callees:
                if edge.target.value in member_eas:
                    internal_calls += 1
                else:
                    external_calls += 1

            total_size += size
            members.append(
                ComponentMember(
                    address=node.address,
                    name=name,
                    size=size,
                    caller_count=len(callers),
                    callee_count=len(callees),
                )
            )

        return Component(
            root=root,
            depth=depth,
            member_count=len(members),
            total_size=total_size,
            internal_call_count=internal_calls,
            external_call_count=external_calls,
            truncated=graph.truncated,
            members=tuple(members),
        )

    @staticmethod
    def _safe_callees(xrefs: XrefRepository, ea: Address):
        """Callees of ``ea``; an unexpandable leaf (import/thunk) counts as none."""
        try:
            return xrefs.callees(ea)
        except (LookupError, RuntimeError):
            return []

    @staticmethod
    def _safe_refs_to(xrefs: XrefRepository, ea: Address):
        """Inbound references to ``ea``; a failed query counts as none."""
        try:
            return xrefs.refs_to(ea)
        except (LookupError, RuntimeError):
            return []
