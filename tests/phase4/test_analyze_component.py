"""Unit tests for the ``analyze_component`` composite tool (no IDA).

Exercises the whole call-subtree roll-up off-host, driven by fake cross-reference
and function repositories and a fake database gateway:

* the pure :class:`~idamesh.domain.services.component.ComponentService` — member
  selection (root plus every node resolving to a real function body), the
  internal-vs-external call-edge split, the aggregate size/count roll-up, member
  ordering, the depth and node bounds with their ``truncated`` flag, name
  precedence (call-graph edge name over the repository name, with a fallback for
  the unnamed root), cycle handling, an import/thunk callee counted as *external*
  and excluded from membership, and an out-of-function root propagating its error;
* the :class:`~idamesh.application.contexts.analyze_component.AnalyzeComponentUseCase`
  — polymorphic selector resolution, the depth clamp to the server ceiling, the
  default depth, and error propagation for an unresolvable or out-of-function root;
* the ``AnalyzeComponentView`` wire-shape projection (addresses as ``0x`` hex,
  nullable ``name`` carried through, nested member list);
* the registered tool — default ``readOnlyHint: true``, the wired ``depth`` default,
  a marshalled invocation, and failures surfaced as ``ToolError`` (``isError``).
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set

import pytest

from idamesh.application.contexts.analyze_component import AnalyzeComponentUseCase
from idamesh.application.dto.analyze_component import (
    COMPONENT_MAX_NODES,
    DEFAULT_COMPONENT_DEPTH,
    MAX_COMPONENT_DEPTH,
    AnalyzeComponentCommand,
    AnalyzeComponentResult,
)
from idamesh.domain.entities.component import Component, ComponentMember
from idamesh.domain.entities.function import Function
from idamesh.domain.entities.xref import Xref, XrefKind, XrefType
from idamesh.domain.services.call_graph import CallGraphService
from idamesh.domain.services.component import ComponentService
from idamesh.domain.values.address import Address, Selector
from idamesh.domain.values.pagination import Page, PageRequest
from idamesh.infrastructure.execution.inline import InlineExecutor
from idamesh.interface.catalog.analyze_component import (
    analyze_component_view,
    register_analyze_component,
)
from idamesh.interface.mcp.engine import ToolError
from idamesh.interface.mcp.registry import Registry

# Concrete EAs used throughout the call-subtree fixtures.
ROOT = 0x1000  # A — the component root
B_EA = 0x2000  # A's callee, itself a caller of D and an import
C_EA = 0x3000  # A's callee, itself a caller of B (a cycle)
D_EA = 0x4000  # B's callee leaf
IMP_EA = 0x9000  # an import slot B calls — a node but not a member


# --------------------------------------------------------------------------- #
# Fakes: xref / function repositories and database gateway (no IDA)
# --------------------------------------------------------------------------- #


class _FakeXrefRepository:
    """Serves ``callees``/``refs_to`` from EA-keyed maps.

    When ``function_eas`` is given, :meth:`callees` on an EA outside that set
    raises ``LookupError`` — mirroring the adapter's out-of-function error, which
    the traversal treats as a graph leaf (or, for the root, propagates). When it
    is ``None`` every EA answers, returning an empty list where none is mapped.
    """

    def __init__(
        self,
        callees_by_ea: Optional[Dict[int, List[Xref]]] = None,
        refs_to_by_ea: Optional[Dict[int, List[Xref]]] = None,
        *,
        function_eas: Optional[Set[int]] = None,
    ) -> None:
        self._callees = dict(callees_by_ea or {})
        self._refs_to = dict(refs_to_by_ea or {})
        self._function_eas = set(function_eas) if function_eas is not None else None

    def callees(self, ea: Address) -> List[Xref]:
        if self._function_eas is not None and int(ea) not in self._function_eas:
            raise LookupError(f"0x{int(ea):x} is not inside a function")
        return list(self._callees.get(int(ea), []))

    def refs_to(self, ea: Address) -> List[Xref]:
        return list(self._refs_to.get(int(ea), []))


class _FakeFunctionRepository:
    """Point lookup by entry EA; unmapped EAs (imports/thunks) answer ``None``."""

    def __init__(self, functions: Optional[Dict[int, Function]] = None) -> None:
        self._functions = dict(functions or {})

    def get(self, ea: Address) -> Optional[Function]:
        return self._functions.get(int(ea))

    # Present only to satisfy the port shape; unused by the roll-up.
    def get_containing(self, ea: Address) -> Optional[Function]:  # pragma: no cover
        return None

    def list(self, page: PageRequest) -> Page[Function]:  # pragma: no cover
        return Page(items=[], offset=page.offset, count=page.count, total=0)

    def count(self) -> int:  # pragma: no cover
        return len(self._functions)


class _FakeDatabase:
    """Resolves selectors: numeric kinds directly, symbols via a name map."""

    def __init__(self, symbols: Optional[Dict[str, int]] = None) -> None:
        self._symbols = dict(symbols or {})

    def resolve_symbol(self, name: str) -> Optional[int]:
        return self._symbols.get(name)

    def resolve(self, selector: Selector) -> Address:
        return selector.resolve(self)


# --------------------------------------------------------------------------- #
# Fixture builders
# --------------------------------------------------------------------------- #


def _call(source: int, target: int, name: Optional[str] = None) -> Xref:
    """A call edge ``source`` -> ``target`` naming the callee at ``target``."""
    return Xref(
        source=Address(source),
        target=Address(target),
        kind=XrefKind.CODE,
        ref_type=XrefType.CALL,
        source_func=None,
        target_name=name,
    )


def _ref_to(target: int, source: int) -> Xref:
    """An inbound reference into ``target`` from ``source`` (count is what matters)."""
    return Xref(
        source=Address(source),
        target=Address(target),
        kind=XrefKind.CODE,
        ref_type=XrefType.CALL,
    )


def _func(ea: int, name: str, size: int) -> Function:
    return Function(ea=Address(ea), name=name, size=size)


def _diamond_graph() -> _FakeXrefRepository:
    """The shared call-subtree fixture.

    ``A -> {B, C}``, ``B -> {D, import}``, ``C -> B`` (a cycle back), ``D`` a leaf.
    ``A/B/C/D`` are real functions; the import at :data:`IMP_EA` is not.
    """
    callees = {
        ROOT: [_call(ROOT, B_EA, "funcB"), _call(ROOT, C_EA, "funcC")],
        B_EA: [_call(B_EA, D_EA, "funcD"), _call(B_EA, IMP_EA, "CreateFileW")],
        C_EA: [_call(C_EA, B_EA, "funcB")],
        D_EA: [],
    }
    refs_to = {
        ROOT: [],
        B_EA: [_ref_to(B_EA, ROOT), _ref_to(B_EA, C_EA)],
        C_EA: [_ref_to(C_EA, ROOT)],
        D_EA: [_ref_to(D_EA, B_EA)],
    }
    return _FakeXrefRepository(callees, refs_to)


def _diamond_functions() -> _FakeFunctionRepository:
    return _FakeFunctionRepository(
        {
            ROOT: _func(ROOT, "rootA", 0x50),
            B_EA: _func(B_EA, "symB", 0x40),
            C_EA: _func(C_EA, "symC", 0x30),
            D_EA: _func(D_EA, "symD", 0x20),
        }
    )


def _member_map(component: Component) -> Dict[int, ComponentMember]:
    return {m.address.value: m for m in component.members}


# --------------------------------------------------------------------------- #
# Service: full roll-up over the whole subtree
# --------------------------------------------------------------------------- #


def test_service_rolls_up_full_subtree_members_and_aggregate_stats():
    service = ComponentService()

    component = service.assemble(
        Address(ROOT), _diamond_graph(), _diamond_functions(), depth=3
    )

    # Members are the root plus every node resolving to a function; the import is
    # excluded. Order follows breadth-first discovery: A, B, C, D.
    assert [m.address.value for m in component.members] == [ROOT, B_EA, C_EA, D_EA]
    assert component.member_count == 4
    # Sizes summed only over members (the import contributes nothing).
    assert component.total_size == 0x50 + 0x40 + 0x30 + 0x20
    # Internal edges: A->B, A->C, B->D, C->B == 4. External: B->import == 1.
    assert component.internal_call_count == 4
    assert component.external_call_count == 1
    assert component.truncated is False
    assert component.root == Address(ROOT)
    assert component.depth == 3


def test_service_member_metrics_are_per_function_degree():
    component = ComponentService().assemble(
        Address(ROOT), _diamond_graph(), _diamond_functions(), depth=3
    )
    by_ea = _member_map(component)

    # callee_count counts every outgoing call edge, internal or external.
    assert by_ea[ROOT].callee_count == 2  # B, C
    assert by_ea[B_EA].callee_count == 2  # D, import
    assert by_ea[C_EA].callee_count == 1  # B
    assert by_ea[D_EA].callee_count == 0

    # caller_count comes straight from refs_to.
    assert by_ea[ROOT].caller_count == 0
    assert by_ea[B_EA].caller_count == 2  # from A and C
    assert by_ea[C_EA].caller_count == 1
    assert by_ea[D_EA].caller_count == 1

    assert by_ea[ROOT].size == 0x50
    assert by_ea[D_EA].size == 0x20


def test_service_import_callee_is_external_and_not_a_member():
    component = ComponentService().assemble(
        Address(ROOT), _diamond_graph(), _diamond_functions(), depth=3
    )
    # The import EA never becomes a member even though it is a discovered node.
    assert IMP_EA not in {m.address.value for m in component.members}
    # Its single inbound call from B is the sole external edge.
    assert component.external_call_count == 1


def test_service_prefers_call_graph_edge_name_over_repository_name():
    component = ComponentService().assemble(
        Address(ROOT), _diamond_graph(), _diamond_functions(), depth=3
    )
    by_ea = _member_map(component)
    # B is discovered via an edge naming it "funcB"; that wins over the repo's
    # "symB". The root, unnamed by any callee edge, falls back to the repo name.
    assert by_ea[B_EA].name == "funcB"
    assert by_ea[C_EA].name == "funcC"
    assert by_ea[D_EA].name == "funcD"
    assert by_ea[ROOT].name == "rootA"


def test_service_root_name_falls_back_to_none_when_unresolved():
    # Root answers callees (so the build succeeds) but has no function record and
    # no naming edge -> its member name is None rather than a crash.
    xrefs = _FakeXrefRepository({ROOT: []})
    component = ComponentService().assemble(
        Address(ROOT), xrefs, _FakeFunctionRepository(), depth=2
    )
    assert component.member_count == 1
    assert component.members[0].name is None
    assert component.members[0].size == 0


# --------------------------------------------------------------------------- #
# Service: depth / node bounds and truncation
# --------------------------------------------------------------------------- #


def test_service_depth_one_stops_at_first_layer_and_flags_truncation():
    component = ComponentService().assemble(
        Address(ROOT), _diamond_graph(), _diamond_functions(), depth=1
    )
    # Only the root and its direct callees are members; D is beyond the bound.
    assert {m.address.value for m in component.members} == {ROOT, B_EA, C_EA}
    assert component.member_count == 3
    # A->B, A->C, C->B stay internal (3). B's calls to D and the import both leave
    # the (now smaller) component -> external == 2.
    assert component.internal_call_count == 3
    assert component.external_call_count == 2
    assert component.truncated is True


def test_service_depth_zero_yields_root_only_all_edges_external():
    component = ComponentService().assemble(
        Address(ROOT), _diamond_graph(), _diamond_functions(), depth=0
    )
    assert [m.address.value for m in component.members] == [ROOT]
    assert component.member_count == 1
    assert component.total_size == 0x50
    assert component.internal_call_count == 0
    # Both of the root's callees are now outside the component.
    assert component.external_call_count == 2
    assert component.truncated is True


def test_service_node_ceiling_bounds_membership_and_flags_truncation():
    # A hard node cap of 2 admits only the root and the first callee explored.
    component = ComponentService().assemble(
        Address(ROOT), _diamond_graph(), _diamond_functions(), depth=5, max_nodes=2
    )
    members = {m.address.value for m in component.members}
    assert members == {ROOT, B_EA}
    assert component.member_count == 2
    assert component.truncated is True
    # A->B is internal; A->C (dropped by the cap) and B->D, B->import are external.
    assert component.internal_call_count == 1
    assert component.external_call_count == 3


def test_service_leaf_only_root_is_not_truncated():
    xrefs = _FakeXrefRepository({ROOT: []})
    functions = _FakeFunctionRepository({ROOT: _func(ROOT, "leaf", 0x10)})
    component = ComponentService().assemble(
        Address(ROOT), xrefs, functions, depth=3
    )
    assert component.member_count == 1
    assert component.internal_call_count == 0
    assert component.external_call_count == 0
    assert component.truncated is False


# --------------------------------------------------------------------------- #
# Service: cycles, recursion, and error propagation
# --------------------------------------------------------------------------- #


def test_service_visits_a_cycle_member_once():
    # B is reached from both A and C; it must appear as a single member.
    component = ComponentService().assemble(
        Address(ROOT), _diamond_graph(), _diamond_functions(), depth=3
    )
    b_members = [m for m in component.members if m.address.value == B_EA]
    assert len(b_members) == 1


def test_service_self_recursive_root_counts_internal_self_edge():
    xrefs = _FakeXrefRepository({ROOT: [_call(ROOT, ROOT, "recur")]})
    functions = _FakeFunctionRepository({ROOT: _func(ROOT, "recur", 0x10)})
    component = ComponentService().assemble(
        Address(ROOT), xrefs, functions, depth=3
    )
    assert component.member_count == 1
    # The self-call targets a member (the root) -> internal, not external.
    assert component.internal_call_count == 1
    assert component.external_call_count == 0


def test_service_out_of_function_root_propagates_error():
    # The root resolves to no function, so callees(root) raises; the traversal
    # re-raises it for the interface to render as isError.
    xrefs = _FakeXrefRepository(function_eas={B_EA})
    with pytest.raises((LookupError, RuntimeError)):
        ComponentService().assemble(
            Address(ROOT), xrefs, _diamond_functions(), depth=2
        )


def test_service_accepts_injected_call_graph_service():
    # The service composes over an injectable CallGraphService instance.
    component = ComponentService(call_graph=CallGraphService()).assemble(
        Address(ROOT), _diamond_graph(), _diamond_functions(), depth=3
    )
    assert component.member_count == 4


# --------------------------------------------------------------------------- #
# Use-case: selector resolution, depth clamp, error propagation
# --------------------------------------------------------------------------- #


def _make_use_case(
    xrefs: _FakeXrefRepository,
    functions: _FakeFunctionRepository,
    symbols: Optional[Dict[str, int]] = None,
) -> AnalyzeComponentUseCase:
    return AnalyzeComponentUseCase(
        database=_FakeDatabase(symbols),
        functions=functions,
        xrefs=xrefs,
        component=ComponentService(),
    )


def test_use_case_resolves_hex_selector_and_rolls_up():
    use_case = _make_use_case(_diamond_graph(), _diamond_functions())

    result = use_case.execute(AnalyzeComponentCommand(address="0x1000", depth=3))

    assert isinstance(result, AnalyzeComponentResult)
    assert result.component.root == Address(ROOT)
    assert result.component.member_count == 4


def test_use_case_resolves_symbol_selector():
    use_case = _make_use_case(
        _diamond_graph(), _diamond_functions(), symbols={"start": ROOT}
    )

    result = use_case.execute(AnalyzeComponentCommand(address="start", depth=2))

    assert result.component.root == Address(ROOT)


def test_use_case_applies_default_depth():
    use_case = _make_use_case(_diamond_graph(), _diamond_functions())

    result = use_case.execute(AnalyzeComponentCommand(address="0x1000"))

    assert DEFAULT_COMPONENT_DEPTH == 2
    assert result.component.depth == DEFAULT_COMPONENT_DEPTH


@pytest.mark.parametrize(
    "requested, expected",
    [
        (0, 0),
        (3, 3),
        (MAX_COMPONENT_DEPTH, MAX_COMPONENT_DEPTH),
        (MAX_COMPONENT_DEPTH + 7, MAX_COMPONENT_DEPTH),
        (-4, 0),
    ],
)
def test_use_case_clamps_depth_to_server_bounds(requested, expected):
    # A single leaf root keeps the roll-up trivial; only the clamped depth matters.
    xrefs = _FakeXrefRepository({ROOT: []})
    functions = _FakeFunctionRepository({ROOT: _func(ROOT, "leaf", 0x10)})
    use_case = _make_use_case(xrefs, functions)

    result = use_case.execute(
        AnalyzeComponentCommand(address="0x1000", depth=requested)
    )

    assert result.component.depth == expected


def test_use_case_uses_the_configured_node_ceiling():
    assert COMPONENT_MAX_NODES == 256


def test_use_case_out_of_function_root_raises():
    xrefs = _FakeXrefRepository(function_eas={B_EA})
    use_case = _make_use_case(xrefs, _diamond_functions())

    with pytest.raises((LookupError, RuntimeError)):
        use_case.execute(AnalyzeComponentCommand(address="0x1000", depth=2))


def test_use_case_unresolvable_symbol_raises():
    use_case = _make_use_case(_diamond_graph(), _diamond_functions())

    with pytest.raises(ValueError):
        use_case.execute(AnalyzeComponentCommand(address="no_such_symbol"))


# --------------------------------------------------------------------------- #
# View projection
# --------------------------------------------------------------------------- #


def test_view_projects_full_wire_shape_with_hex_addresses():
    component = Component(
        root=Address(0x140001000),
        depth=2,
        member_count=2,
        total_size=0x90,
        internal_call_count=1,
        external_call_count=3,
        truncated=True,
        members=(
            ComponentMember(
                address=Address(0x140001000),
                name="root",
                size=0x50,
                caller_count=0,
                callee_count=2,
            ),
            ComponentMember(
                address=Address(0x140002000),
                name=None,
                size=0x40,
                caller_count=1,
                callee_count=0,
            ),
        ),
    )

    view = analyze_component_view(AnalyzeComponentResult(component=component))

    assert view == {
        "root": "0x140001000",
        "depth": 2,
        "member_count": 2,
        "total_size": 0x90,
        "internal_call_count": 1,
        "external_call_count": 3,
        "truncated": True,
        "members": [
            {
                "address": "0x140001000",
                "name": "root",
                "size": 0x50,
                "caller_count": 0,
                "callee_count": 2,
            },
            {
                "address": "0x140002000",
                "name": None,
                "size": 0x40,
                "caller_count": 1,
                "callee_count": 0,
            },
        ],
    }


def test_view_of_single_member_component():
    component = Component(
        root=Address(ROOT),
        depth=0,
        member_count=1,
        total_size=0x10,
        internal_call_count=0,
        external_call_count=0,
        truncated=False,
        members=(
            ComponentMember(
                address=Address(ROOT),
                name="only",
                size=0x10,
                caller_count=0,
                callee_count=0,
            ),
        ),
    )

    view = analyze_component_view(AnalyzeComponentResult(component=component))

    assert view["member_count"] == 1
    assert view["members"] == [
        {
            "address": "0x1000",
            "name": "only",
            "size": 0x10,
            "caller_count": 0,
            "callee_count": 0,
        }
    ]


# --------------------------------------------------------------------------- #
# Registered tool: annotations + invocation
# --------------------------------------------------------------------------- #


def _register(use_case: AnalyzeComponentUseCase) -> Registry:
    registry = Registry()
    register_analyze_component(
        registry,
        analyze_component_use_case=use_case,
        executor=InlineExecutor(),
    )
    return registry


def test_tool_is_advertised_read_only():
    use_case = _make_use_case(_diamond_graph(), _diamond_functions())
    spec = _register(use_case).get_tool("analyze_component")

    assert spec is not None
    assert spec.annotations["readOnlyHint"] is True


def test_tool_wired_default_depth_matches_dto():
    use_case = _make_use_case(_diamond_graph(), _diamond_functions())
    spec = _register(use_case).get_tool("analyze_component")

    # Invoked with only the address -> the wired signature applies depth == 2.
    result = spec.invoke(address="0x1000")

    assert result["depth"] == DEFAULT_COMPONENT_DEPTH


def test_tool_invocation_returns_projected_view():
    use_case = _make_use_case(_diamond_graph(), _diamond_functions())
    spec = _register(use_case).get_tool("analyze_component")

    result = spec.invoke(address="0x1000", depth=3)

    assert result["root"] == "0x1000"
    assert result["member_count"] == 4
    assert result["internal_call_count"] == 4
    assert result["external_call_count"] == 1
    assert result["truncated"] is False
    assert [m["address"] for m in result["members"]] == [
        "0x1000",
        "0x2000",
        "0x3000",
        "0x4000",
    ]


def test_tool_out_of_function_root_is_surfaced_as_tool_error():
    xrefs = _FakeXrefRepository(function_eas={B_EA})
    spec = _register(_make_use_case(xrefs, _diamond_functions())).get_tool(
        "analyze_component"
    )

    with pytest.raises(ToolError):
        spec.invoke(address="0x1000", depth=2)


def test_tool_unresolvable_symbol_is_surfaced_as_tool_error():
    spec = _register(_make_use_case(_diamond_graph(), _diamond_functions())).get_tool(
        "analyze_component"
    )

    with pytest.raises(ToolError):
        spec.invoke(address="does_not_exist")
