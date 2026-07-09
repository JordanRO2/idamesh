"""Unit tests for the ``callgraph`` service, use-case, and view (no IDA).

A fake :class:`XrefRepository` supplies a fixed callee graph and a fake database
gateway resolves selectors through the real :class:`Selector`, so the bounded
breadth-first traversal, its depth/node bounds, cycle handling, selector
resolution, and wire projection are all exercised without a database present.
"""

from __future__ import annotations

import pytest

from idamesh.application.contexts.call_graph import CallgraphUseCase
from idamesh.application.dto.call_graph import (
    MAX_CALLGRAPH_DEPTH,
    MAX_CALLGRAPH_NODES,
    CallgraphCommand,
    CallgraphResult,
)
from idamesh.domain.entities.call_graph import CallGraph, CallGraphEdge, CallGraphNode
from idamesh.domain.entities.xref import Xref, XrefKind, XrefType
from idamesh.domain.services.call_graph import DEFAULT_MAX_NODES, CallGraphService
from idamesh.domain.values.address import Address, Selector
from idamesh.interface.catalog.callgraph import (
    call_graph_edge_view,
    call_graph_node_view,
    callgraph_view,
)


class _FakeDatabase:
    """A resolver-backed database gateway over a fixed symbol table."""

    def __init__(self, symbols: dict[str, int] | None = None) -> None:
        self._symbols = symbols or {}

    def resolve_symbol(self, name: str) -> int | None:
        return self._symbols.get(name)

    def resolve(self, selector: Selector) -> Address:
        return selector.resolve(self)


class _FakeXrefRepository:
    """An in-memory ``XrefRepository`` over a fixed callee-edge graph.

    ``calls`` maps a function EA to its outgoing call edges; ``no_function`` names
    EAs that lie inside no function, for which :meth:`callees` raises (mirroring
    the real adapter's out-of-function failure).
    """

    def __init__(
        self,
        calls: dict[int, list[Xref]] | None = None,
        no_function: set[int] | None = None,
    ) -> None:
        self._calls = calls or {}
        self._no_function = no_function or set()
        self.callees_seen: list[Address] = []

    def refs_to(self, ea: Address) -> list[Xref]:  # unused by callgraph
        return []

    def callees(self, ea: Address) -> list[Xref]:
        self.callees_seen.append(ea)
        if int(ea) in self._no_function:
            raise LookupError(f"no function contains {ea.hex()}")
        return list(self._calls.get(int(ea), []))


def _edge(dst: int, name: str | None = None) -> Xref:
    """A call edge to ``dst``; the source is irrelevant to the traversal."""
    return Xref(
        source=Address(0x1),
        target=Address(dst),
        kind=XrefKind.CODE,
        ref_type=XrefType.CALL,
        target_name=name,
    )


def _chain() -> _FakeXrefRepository:
    """A straight chain A -> B -> C -> D (D is a leaf)."""
    return _FakeXrefRepository(
        calls={
            0xA: [_edge(0xB, "B")],
            0xB: [_edge(0xC, "C")],
            0xC: [_edge(0xD, "D")],
        }
    )


# -- service: depth bound ---------------------------------------------------


def test_build_depth_one_expands_a_single_layer():
    graph = CallGraphService().build(Address(0xA), _chain(), depth=1)

    assert graph.root == Address(0xA)
    assert {n.address.value for n in graph.nodes} == {0xA, 0xB}
    assert {(e.source.value, e.target.value) for e in graph.edges} == {(0xA, 0xB)}
    # B still has an unexplored callee (C), so the depth bound truncated.
    assert graph.truncated is True


def test_build_depth_two_expands_two_layers():
    graph = CallGraphService().build(Address(0xA), _chain(), depth=2)

    assert {n.address.value for n in graph.nodes} == {0xA, 0xB, 0xC}
    assert {(e.source.value, e.target.value) for e in graph.edges} == {
        (0xA, 0xB),
        (0xB, 0xC),
    }
    assert graph.truncated is True


def test_build_depth_covers_whole_graph_without_truncation():
    graph = CallGraphService().build(Address(0xA), _chain(), depth=3)

    assert {n.address.value for n in graph.nodes} == {0xA, 0xB, 0xC, 0xD}
    assert {(e.source.value, e.target.value) for e in graph.edges} == {
        (0xA, 0xB),
        (0xB, 0xC),
        (0xC, 0xD),
    }
    # D is a leaf at the frontier: nothing elided.
    assert graph.truncated is False


def test_build_depth_zero_returns_only_root():
    graph = CallGraphService().build(Address(0xA), _chain(), depth=0)

    assert {n.address.value for n in graph.nodes} == {0xA}
    assert graph.edges == ()
    # The root has callees that depth=0 elided.
    assert graph.truncated is True


def test_build_negative_depth_is_treated_as_zero():
    graph = CallGraphService().build(Address(0xA), _chain(), depth=-5)

    assert {n.address.value for n in graph.nodes} == {0xA}
    assert graph.edges == ()
    assert graph.truncated is True


def test_build_leaf_root_is_not_truncated():
    repo = _FakeXrefRepository(calls={0xA: []})

    graph = CallGraphService().build(Address(0xA), repo, depth=3)

    assert {n.address.value for n in graph.nodes} == {0xA}
    assert graph.edges == ()
    assert graph.truncated is False


# -- service: cycles --------------------------------------------------------


def test_build_visits_a_cycle_once_and_keeps_both_edges():
    repo = _FakeXrefRepository(
        calls={
            0xA: [_edge(0xB, "B")],
            0xB: [_edge(0xA, "A")],
        }
    )

    graph = CallGraphService().build(Address(0xA), repo, depth=8)

    assert {n.address.value for n in graph.nodes} == {0xA, 0xB}
    assert {(e.source.value, e.target.value) for e in graph.edges} == {
        (0xA, 0xB),
        (0xB, 0xA),
    }
    # Every reachable function was expanded; the cycle closed without truncation.
    assert graph.truncated is False
    # Each distinct function is walked exactly once.
    assert repo.callees_seen == [Address(0xA), Address(0xB)]


def test_build_backfills_root_name_when_reached_via_cycle():
    repo = _FakeXrefRepository(
        calls={
            0xA: [_edge(0xB, "B")],
            0xB: [_edge(0xA, "A")],
        }
    )

    graph = CallGraphService().build(Address(0xA), repo, depth=8)

    names = {n.address.value: n.name for n in graph.nodes}
    assert names == {0xA: "A", 0xB: "B"}


def test_build_self_loop_visited_once():
    repo = _FakeXrefRepository(calls={0xA: [_edge(0xA, "A")]})

    graph = CallGraphService().build(Address(0xA), repo, depth=5)

    assert {n.address.value for n in graph.nodes} == {0xA}
    assert {(e.source.value, e.target.value) for e in graph.edges} == {(0xA, 0xA)}
    assert repo.callees_seen == [Address(0xA)]
    assert graph.truncated is False


# -- service: node cap ------------------------------------------------------


def test_build_node_cap_truncates_and_drops_edges_into_dropped_nodes():
    repo = _FakeXrefRepository(
        calls={0xA: [_edge(0x100 + i, f"f{i}") for i in range(10)]}
    )

    graph = CallGraphService().build(Address(0xA), repo, depth=1, max_nodes=3)

    # Root plus exactly two callees fit under the ceiling of three.
    assert len(graph.nodes) == 3
    assert {n.address.value for n in graph.nodes} == {0xA, 0x100, 0x101}
    # No edge points at a node that was dropped.
    node_eas = {n.address.value for n in graph.nodes}
    for edge in graph.edges:
        assert edge.target.value in node_eas
    assert len(graph.edges) == 2
    assert graph.truncated is True


def test_build_at_node_cap_boundary_is_not_truncated():
    repo = _FakeXrefRepository(calls={0xA: [_edge(0xB, "B"), _edge(0xC, "C")]})

    graph = CallGraphService().build(Address(0xA), repo, depth=1, max_nodes=3)

    assert {n.address.value for n in graph.nodes} == {0xA, 0xB, 0xC}
    assert graph.truncated is False


def test_build_default_max_nodes_is_a_thousand():
    assert DEFAULT_MAX_NODES == 1000


# -- service: out-of-function ----------------------------------------------


def test_build_out_of_function_root_propagates_error():
    repo = _FakeXrefRepository(no_function={0x600100})

    with pytest.raises(LookupError):
        CallGraphService().build(Address(0x600100), repo, depth=3)


def test_build_interior_out_of_function_callee_is_a_leaf_not_an_abort():
    # A -> B, A -> T, where T is an import/thunk that lies inside no function.
    # T must appear as a reached node and edge, but the failure to enumerate its
    # callees must not abort the whole traversal (B and its callee C survive).
    repo = _FakeXrefRepository(
        calls={
            0xA: [_edge(0xB, "B"), _edge(0x7, "imp_thunk")],
            0xB: [_edge(0xC, "C")],
        },
        no_function={0x7},
    )

    graph = CallGraphService().build(Address(0xA), repo, depth=5)

    assert {n.address.value for n in graph.nodes} == {0xA, 0xB, 0xC, 0x7}
    edge_pairs = {(e.source.value, e.target.value) for e in graph.edges}
    assert edge_pairs == {(0xA, 0xB), (0xA, 0x7), (0xB, 0xC)}
    # The thunk was probed for callees (and failed) but yielded no children; the
    # rest of the graph is fully explored, so nothing was elided.
    assert Address(0x7) in repo.callees_seen
    assert graph.truncated is False


def test_build_dedupes_repeated_edge_to_same_target():
    # A diamond: A -> B, A -> C, B -> D, C -> D. D is reached twice.
    repo = _FakeXrefRepository(
        calls={
            0xA: [_edge(0xB, "B"), _edge(0xC, "C")],
            0xB: [_edge(0xD, "D")],
            0xC: [_edge(0xD, "D")],
        }
    )

    graph = CallGraphService().build(Address(0xA), repo, depth=5)

    assert {n.address.value for n in graph.nodes} == {0xA, 0xB, 0xC, 0xD}
    edge_pairs = [(e.source.value, e.target.value) for e in graph.edges]
    assert sorted(edge_pairs) == [(0xA, 0xB), (0xA, 0xC), (0xB, 0xD), (0xC, 0xD)]
    # D is materialized as a node once and walked once.
    assert repo.callees_seen.count(Address(0xD)) == 1
    assert graph.truncated is False


# -- use-case: resolution + clamping ---------------------------------------


def test_use_case_resolves_hex_and_builds_graph():
    use_case = CallgraphUseCase(_chain(), _FakeDatabase())

    result = use_case.execute(CallgraphCommand(address="0xa", depth=3))

    assert isinstance(result, CallgraphResult)
    assert result.graph.root == Address(0xA)
    assert {n.address.value for n in result.graph.nodes} == {0xA, 0xB, 0xC, 0xD}


def test_use_case_resolves_decimal_and_symbol():
    repo = _FakeXrefRepository(calls={0xA: [_edge(0xB, "B")]})
    database = _FakeDatabase(symbols={"start": 0xA})

    dec = CallgraphUseCase(repo, _FakeDatabase()).execute(
        CallgraphCommand(address="10")
    )
    assert dec.graph.root == Address(0xA)

    sym = CallgraphUseCase(repo, database).execute(CallgraphCommand(address="start"))
    assert sym.graph.root == Address(0xA)


def test_use_case_unresolvable_symbol_raises():
    use_case = CallgraphUseCase(_FakeXrefRepository(), _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(CallgraphCommand(address="ghost"))


def test_use_case_out_of_function_propagates_error():
    repo = _FakeXrefRepository(no_function={0xA})
    use_case = CallgraphUseCase(repo, _FakeDatabase())

    with pytest.raises(LookupError):
        use_case.execute(CallgraphCommand(address="0xa"))


class _SpyService:
    """Records the bounds handed to :meth:`build` and returns a canned graph."""

    def __init__(self) -> None:
        self.depth: int | None = None
        self.max_nodes: int | None = None

    def build(self, root, xrefs, *, depth, max_nodes=DEFAULT_MAX_NODES):
        self.depth = depth
        self.max_nodes = max_nodes
        return CallGraph(root=root)


def test_use_case_clamps_depth_to_server_maximum():
    use_case = CallgraphUseCase(_FakeXrefRepository(), _FakeDatabase())
    spy = _SpyService()
    use_case._service = spy  # type: ignore[assignment]

    use_case.execute(CallgraphCommand(address="0xa", depth=10_000))

    assert spy.depth == MAX_CALLGRAPH_DEPTH
    assert spy.max_nodes == MAX_CALLGRAPH_NODES


def test_use_case_floors_negative_depth_at_zero():
    use_case = CallgraphUseCase(_FakeXrefRepository(), _FakeDatabase())
    spy = _SpyService()
    use_case._service = spy  # type: ignore[assignment]

    use_case.execute(CallgraphCommand(address="0xa", depth=-3))

    assert spy.depth == 0


def test_use_case_passes_in_range_depth_through():
    use_case = CallgraphUseCase(_FakeXrefRepository(), _FakeDatabase())
    spy = _SpyService()
    use_case._service = spy  # type: ignore[assignment]

    use_case.execute(CallgraphCommand(address="0xa", depth=4))

    assert spy.depth == 4


# -- views ------------------------------------------------------------------


def test_call_graph_node_view_projects_named_and_anonymous():
    named = call_graph_node_view(CallGraphNode(address=Address(0x402000), name="helper"))
    anon = call_graph_node_view(CallGraphNode(address=Address(0x403000)))

    assert named == {"address": "0x402000", "name": "helper"}
    assert anon == {"address": "0x403000", "name": None}


def test_call_graph_edge_view_uses_from_and_to_keys():
    view = call_graph_edge_view(
        CallGraphEdge(source=Address(0x401000), target=Address(0x402000))
    )

    assert view == {"from": "0x401000", "to": "0x402000"}


def test_callgraph_view_projects_result():
    graph = CallGraph(
        root=Address(0x401000),
        nodes=(
            CallGraphNode(address=Address(0x401000), name="main"),
            CallGraphNode(address=Address(0x402000), name="helper"),
        ),
        edges=(CallGraphEdge(source=Address(0x401000), target=Address(0x402000)),),
        truncated=True,
    )

    view = callgraph_view(CallgraphResult(graph=graph))

    assert view["root"] == "0x401000"
    assert view["nodes"] == [
        {"address": "0x401000", "name": "main"},
        {"address": "0x402000", "name": "helper"},
    ]
    assert view["edges"] == [{"from": "0x401000", "to": "0x402000"}]
    assert view["truncated"] is True
