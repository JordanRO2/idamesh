"""Unit tests for ``analyze_function`` — the single-function composite (no IDA).

``analyze_function`` owns no adapter of its own: it wires the four existing
per-tool read use-cases (``func_profile`` / ``decompile`` / ``xrefs_to`` /
``callees``) plus the import repository into one bundle. These tests exercise the
*real* sub-use-cases driven entirely by in-memory fakes for their ports — a fake
database resolver, function repository, cross-reference repository, basic-block
gateway, decompiler, and import table — so the composite's own derivations are
asserted with no database:

* the assembly itself — profile, pseudocode, caller/callee edges all threaded
  through from the delegates onto the flat :class:`FunctionAnalysis`;
* the two cheap extras the composite derives without a new port — the
  ``import_references`` (callee names that are imported symbols, deduped in call
  order) and the ``string_literals`` scraped out of the pseudocode (deduped,
  order-preserving, capped);
* the failure surface — an out-of-function address, an unresolvable symbol, and
  an unavailable decompiler each surface as an error rather than a partial
  bundle; and
* the catalog projection and registration — the flat wire shape and the
  read-only tool wiring.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple, TypeVar

import pytest

from idamesh.application.contexts.analyze_function import (
    ANALYZE_IMPORT_SCAN,
    ANALYZE_STRING_LITERALS,
    AnalyzeFunctionUseCase,
)
from idamesh.application.contexts.decompiler import DecompileUseCase
from idamesh.application.contexts.func_profile import FuncProfileUseCase
from idamesh.application.contexts.xrefs import CalleesUseCase, XrefsToUseCase
from idamesh.application.dto.analyze_function import (
    AnalyzeFunctionCommand,
    AnalyzeFunctionResult,
)
from idamesh.domain.entities.analyze_function import FunctionAnalysis
from idamesh.domain.entities.basic_block import BasicBlock
from idamesh.domain.entities.decompilation import Pseudocode
from idamesh.domain.entities.func_profile import FuncProfile
from idamesh.domain.entities.function import Function
from idamesh.domain.entities.imports import Import
from idamesh.domain.entities.xref import Xref, XrefKind, XrefType
from idamesh.domain.values.address import Address, Selector
from idamesh.domain.values.pagination import Page, PageRequest
from idamesh.interface.catalog.analyze_function import (
    AnalyzeFunctionView,
    analyze_function_view,
    register_analyze_function,
)
from idamesh.interface.mcp.engine import ToolError
from idamesh.interface.mcp.registry import Registry

T = TypeVar("T")


# -- fakes ------------------------------------------------------------------


class _FakeDatabase:
    """A resolver-backed ``DatabaseGateway`` over an in-memory symbol table.

    Hex/decimal selectors parse directly (as the value object does); a symbol
    selector looks up ``symbols`` and raises the same ``ValueError`` the real
    gateway raises when the name is unknown.
    """

    def __init__(self, symbols: Optional[Dict[str, int]] = None) -> None:
        self._symbols = dict(symbols or {})

    def resolve(self, selector: Selector) -> Address:
        return selector.resolve(self)

    def resolve_symbol(self, name: str) -> Optional[int]:
        return self._symbols.get(name)

    def is_open(self) -> bool:
        return True


class _FakeFunctions:
    """An in-memory ``FunctionRepository`` backed by a list of functions."""

    def __init__(self, functions: Sequence[Function]) -> None:
        self._functions = list(functions)

    def _end(self, func: Function) -> int:
        return int(func.end_ea) if func.end_ea is not None else int(func.ea) + func.size

    def get(self, ea: Address) -> Optional[Function]:
        for func in self._functions:
            if func.ea == ea:
                return func
        return None

    def get_containing(self, ea: Address) -> Optional[Function]:
        value = int(ea)
        for func in self._functions:
            if int(func.ea) <= value < self._end(func):
                return func
        return None

    def list(self, page: PageRequest) -> Page[Function]:
        window = self._functions[page.offset : page.offset + page.count]
        return Page(
            items=window,
            offset=page.offset,
            count=page.count,
            total=len(self._functions),
        )

    def count(self) -> int:
        return len(self._functions)


class _FakeXrefs:
    """An in-memory ``XrefRepository`` keyed by anchor-address value."""

    def __init__(
        self,
        refs_to: Optional[Dict[int, List[Xref]]] = None,
        callees: Optional[Dict[int, List[Xref]]] = None,
    ) -> None:
        self._refs_to = refs_to or {}
        self._callees = callees or {}

    def refs_to(self, ea: Address) -> List[Xref]:
        return list(self._refs_to.get(int(ea), []))

    def callees(self, ea: Address) -> List[Xref]:
        return list(self._callees.get(int(ea), []))


class _FakeBlocks:
    """An in-memory ``BasicBlockGateway`` keyed by entry-address value."""

    def __init__(self, blocks: Optional[Dict[int, List[BasicBlock]]] = None) -> None:
        self._blocks = blocks or {}

    def blocks(self, ea: Address) -> List[BasicBlock]:
        return list(self._blocks.get(int(ea), []))


class _FakeDecompiler:
    """An in-memory ``DecompilerGateway`` keyed by resolved-address value."""

    def __init__(
        self,
        pseudocode: Optional[Dict[int, Pseudocode]] = None,
        *,
        unavailable: bool = False,
    ) -> None:
        self._pseudocode = pseudocode or {}
        self._unavailable = unavailable

    def is_available(self) -> bool:
        return not self._unavailable

    def decompile(self, ea: Address) -> Pseudocode:
        if self._unavailable:
            raise RuntimeError("decompiler is not available")
        try:
            return self._pseudocode[int(ea)]
        except KeyError:  # pragma: no cover - guard for a misconfigured scenario
            raise ValueError(f"no function to decompile at {ea.hex()}")


class _FakeImports:
    """An in-memory ``ImportRepository`` that records the page it was asked for."""

    def __init__(self, imports: Sequence[Import]) -> None:
        self._imports = list(imports)
        self.pages: List[PageRequest] = []

    def list(self, page: PageRequest) -> Page[Import]:
        self.pages.append(page)
        window = self._imports[page.offset : page.offset + page.count]
        return Page(
            items=window,
            offset=page.offset,
            count=page.count,
            total=len(self._imports),
        )

    def count(self) -> int:
        return len(self._imports)


@dataclass
class _InlineExecutor:
    """A ``MainThreadExecutor`` that runs jobs inline, recording write affinity."""

    write_flags: List[bool] = field(default_factory=list)

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        self.write_flags.append(write)
        return job()

    def on_kernel_thread(self) -> bool:
        return True


# -- scenario builders ------------------------------------------------------


def _call_edge(source: int, target: int, name: Optional[str]) -> Xref:
    """A code CALL edge out of a function, carrying the callee's ``target_name``."""
    return Xref(
        source=Address(source),
        target=Address(target),
        kind=XrefKind.CODE,
        ref_type=XrefType.CALL,
        target_name=name,
    )


def _caller_edge(source: int, target: int, func: Optional[str]) -> Xref:
    """A code CALL edge into a function, carrying the source's enclosing ``func``."""
    return Xref(
        source=Address(source),
        target=Address(target),
        kind=XrefKind.CODE,
        ref_type=XrefType.CALL,
        source_func=func,
    )


#: Entry of the function every default scenario analyses.
ENTRY = 0x401000


def _build_use_case(
    *,
    functions: _FakeFunctions,
    xrefs: _FakeXrefs,
    blocks: _FakeBlocks,
    decompiler: _FakeDecompiler,
    imports: _FakeImports,
    database: _FakeDatabase,
) -> AnalyzeFunctionUseCase:
    """Wire the four real sub-use-cases over the fakes into the composite."""
    return AnalyzeFunctionUseCase(
        func_profile=FuncProfileUseCase(
            functions=functions, xrefs=xrefs, blocks=blocks, database=database
        ),
        decompile=DecompileUseCase(decompiler=decompiler, database=database),
        xrefs_to=XrefsToUseCase(xrefs=xrefs, database=database),
        callees=CalleesUseCase(xrefs=xrefs, database=database),
        imports=imports,
    )


def _default_scenario() -> Tuple[AnalyzeFunctionUseCase, _FakeImports]:
    """A rich, self-consistent function to analyse.

    ``process_data`` @ ``0x401000`` has three CFG blocks, two callers, and four
    callee edges — two to imported symbols (one of them called twice), one to an
    internal helper, plus the deduped import. Its pseudocode carries two distinct
    string literals, one of them repeated.
    """
    func = Function(
        ea=Address(ENTRY),
        name="process_data",
        size=0x60,
        end_ea=Address(ENTRY + 0x60),
    )
    functions = _FakeFunctions([func])

    blocks = _FakeBlocks(
        {
            ENTRY: [
                BasicBlock(
                    start=Address(0x401000),
                    end=Address(0x401020),
                    successors=(Address(0x401020), Address(0x401040)),
                ),
                BasicBlock(
                    start=Address(0x401020),
                    end=Address(0x401040),
                    successors=(Address(0x401040),),
                ),
                BasicBlock(
                    start=Address(0x401040),
                    end=Address(0x401060),
                    successors=(),
                ),
            ]
        }
    )

    xrefs = _FakeXrefs(
        refs_to={
            ENTRY: [
                _caller_edge(0x400F00, ENTRY, "main"),
                _caller_edge(0x400F50, ENTRY, "init"),
            ]
        },
        callees={
            ENTRY: [
                _call_edge(0x401010, 0x600100, "malloc"),
                _call_edge(0x401024, 0x600108, "strcpy"),
                _call_edge(0x401030, 0x401200, "helper"),
                _call_edge(0x401044, 0x600100, "malloc"),  # duplicate import call
            ]
        },
    )

    lines = (
        "void process_data(char *a1)",
        "{",
        '  char *v1 = malloc(0x20);',
        '  strcpy(v1, "hello %s");',
        '  log_msg("hello %s");',
        '  helper(v1, "/tmp/output");',
        "}",
    )
    decompiler = _FakeDecompiler(
        {ENTRY: Pseudocode(ea=Address(ENTRY), text="\n".join(lines), lines=lines)}
    )

    imports = _FakeImports(
        [
            Import(ea=Address(0x600100), name="malloc", module="msvcrt"),
            Import(ea=Address(0x600108), name="strcpy", module="msvcrt"),
            Import(ea=Address(0x600110), name="free", module="msvcrt"),
        ]
    )

    use_case = _build_use_case(
        functions=functions,
        xrefs=xrefs,
        blocks=blocks,
        decompiler=decompiler,
        imports=imports,
        database=_FakeDatabase(symbols={"process_data": ENTRY}),
    )
    return use_case, imports


# -- composite assembly -----------------------------------------------------


def test_composite_threads_every_delegate_onto_one_report():
    use_case, _ = _default_scenario()

    analysis = use_case.execute(AnalyzeFunctionCommand(address=hex(ENTRY))).analysis

    # profile — aggregated by the real func_profile use-case over the fakes.
    assert analysis.profile.address == Address(ENTRY)
    assert analysis.profile.name == "process_data"
    assert analysis.profile.size == 0x60
    assert analysis.profile.block_count == 3
    assert analysis.profile.edge_count == 3  # 2 + 1 + 0 successors
    assert analysis.profile.caller_count == 2
    assert analysis.profile.callee_count == 4

    # pseudocode — passed straight through, text and split lines both preserved.
    assert analysis.pseudocode.text.splitlines()[0] == "void process_data(char *a1)"
    assert len(analysis.pseudocode.lines) == 7

    # edges — callers from refs_to, callees from callees, in source order.
    assert tuple(edge.source_func for edge in analysis.callers) == ("main", "init")
    assert tuple(edge.target_name for edge in analysis.callees) == (
        "malloc",
        "strcpy",
        "helper",
        "malloc",
    )


def test_import_references_keep_only_imported_callees_deduped_in_call_order():
    use_case, _ = _default_scenario()

    analysis = use_case.execute(AnalyzeFunctionCommand(address=hex(ENTRY))).analysis

    # "helper" is internal (not an import); the second "malloc" call is a
    # duplicate; "free" is imported but never called. Order follows the callees.
    assert analysis.import_references == ("malloc", "strcpy")


def test_import_references_empty_when_no_callee_is_imported():
    func = Function(ea=Address(ENTRY), name="leaf", size=0x10, end_ea=Address(ENTRY + 0x10))
    xrefs = _FakeXrefs(
        refs_to={ENTRY: []},
        callees={ENTRY: [_call_edge(0x401004, 0x401200, "helper")]},
    )
    blocks = _FakeBlocks({ENTRY: [BasicBlock(Address(ENTRY), Address(ENTRY + 0x10))]})
    decompiler = _FakeDecompiler(
        {ENTRY: Pseudocode(ea=Address(ENTRY), text="return helper();", lines=())}
    )
    use_case = _build_use_case(
        functions=_FakeFunctions([func]),
        xrefs=xrefs,
        blocks=blocks,
        decompiler=decompiler,
        imports=_FakeImports([Import(ea=Address(0x600100), name="malloc", module="m")]),
        database=_FakeDatabase(),
    )

    analysis = use_case.execute(AnalyzeFunctionCommand(address=hex(ENTRY))).analysis

    assert analysis.import_references == ()


def test_import_reference_scan_requests_the_published_page_size():
    use_case, imports = _default_scenario()

    use_case.execute(AnalyzeFunctionCommand(address=hex(ENTRY)))

    # The composite pulls the import table with its declared scan window so the
    # callee names can be matched — it is not left to the default page size.
    assert imports.pages, "the import table was never scanned"
    assert imports.pages[0].count == ANALYZE_IMPORT_SCAN
    assert imports.pages[0].offset == 0


def test_string_literals_are_scraped_deduped_and_order_preserving():
    use_case, _ = _default_scenario()

    analysis = use_case.execute(AnalyzeFunctionCommand(address=hex(ENTRY))).analysis

    # "hello %s" appears twice in the pseudocode; the numeric 0x20 is not quoted.
    assert analysis.string_literals == ("hello %s", "/tmp/output")


def test_string_literals_are_capped_at_the_published_maximum():
    func = Function(ea=Address(ENTRY), name="chatty", size=0x10, end_ea=Address(ENTRY + 0x10))
    # More distinct quoted tokens than the cap admits.
    literals = [f"s{i}" for i in range(ANALYZE_STRING_LITERALS + 8)]
    text = " ".join(f'"{value}"' for value in literals)
    use_case = _build_use_case(
        functions=_FakeFunctions([func]),
        xrefs=_FakeXrefs(refs_to={ENTRY: []}, callees={ENTRY: []}),
        blocks=_FakeBlocks({ENTRY: [BasicBlock(Address(ENTRY), Address(ENTRY + 0x10))]}),
        decompiler=_FakeDecompiler({ENTRY: Pseudocode(ea=Address(ENTRY), text=text)}),
        imports=_FakeImports([]),
        database=_FakeDatabase(),
    )

    analysis = use_case.execute(AnalyzeFunctionCommand(address=hex(ENTRY))).analysis

    assert len(analysis.string_literals) == ANALYZE_STRING_LITERALS
    assert analysis.string_literals[0] == "s0"
    assert analysis.string_literals[-1] == f"s{ANALYZE_STRING_LITERALS - 1}"


def test_symbol_selector_resolves_the_same_function_as_its_address():
    use_case, _ = _default_scenario()

    by_symbol = use_case.execute(AnalyzeFunctionCommand(address="process_data")).analysis

    assert by_symbol.profile.address == Address(ENTRY)
    assert by_symbol.import_references == ("malloc", "strcpy")


# -- failure surface --------------------------------------------------------


def test_address_in_no_function_raises_rather_than_returning_a_partial_bundle():
    # 0x500000 resolves fine but lies outside every function body.
    use_case, _ = _default_scenario()

    with pytest.raises(LookupError):
        use_case.execute(AnalyzeFunctionCommand(address="0x500000"))


def test_unresolvable_symbol_raises():
    use_case, _ = _default_scenario()

    with pytest.raises(ValueError):
        use_case.execute(AnalyzeFunctionCommand(address="does_not_exist"))


def test_unavailable_decompiler_raises_after_the_profile_succeeds():
    func = Function(ea=Address(ENTRY), name="fn", size=0x10, end_ea=Address(ENTRY + 0x10))
    use_case = _build_use_case(
        functions=_FakeFunctions([func]),
        xrefs=_FakeXrefs(refs_to={ENTRY: []}, callees={ENTRY: []}),
        blocks=_FakeBlocks({ENTRY: [BasicBlock(Address(ENTRY), Address(ENTRY + 0x10))]}),
        decompiler=_FakeDecompiler(unavailable=True),
        imports=_FakeImports([]),
        database=_FakeDatabase(),
    )

    with pytest.raises(RuntimeError):
        use_case.execute(AnalyzeFunctionCommand(address=hex(ENTRY)))


# -- view projection --------------------------------------------------------


def _analysis_fixture() -> FunctionAnalysis:
    profile = FuncProfile(
        address=Address(ENTRY),
        name="process_data",
        size=0x60,
        block_count=3,
        edge_count=3,
        caller_count=2,
        callee_count=2,
    )
    pseudocode = Pseudocode(
        ea=Address(ENTRY),
        text='void process_data()\n{\n  puts("hi");\n}',
        lines=("void process_data()", "{", '  puts("hi");', "}"),
    )
    return FunctionAnalysis(
        profile=profile,
        pseudocode=pseudocode,
        callers=(_caller_edge(0x400F00, ENTRY, "main"),),
        callees=(_call_edge(0x401010, 0x600100, "puts"),),
        import_references=("puts",),
        string_literals=("hi",),
    )


def test_view_projects_the_flat_wire_shape():
    view = analyze_function_view(AnalyzeFunctionResult(analysis=_analysis_fixture()))

    assert view["address"] == "0x401000"
    assert view["name"] == "process_data"
    assert view["profile"] == {
        "address": "0x401000",
        "name": "process_data",
        "size": 0x60,
        "block_count": 3,
        "edge_count": 3,
        "caller_count": 2,
        "callee_count": 2,
    }
    assert view["pseudocode"].startswith("void process_data()")
    assert view["lines"] == ["void process_data()", "{", '  puts("hi");', "}"]
    assert view["callers"] == [
        {
            "from": "0x400f00",
            "to": "0x401000",
            "kind": "code",
            "type": "call",
            "func": "main",
        }
    ]
    assert view["callees"] == [
        {
            "from": "0x401010",
            "to": "0x600100",
            "kind": "code",
            "type": "call",
            "func": None,
        }
    ]
    assert view["import_references"] == ["puts"]
    assert view["string_literals"] == ["hi"]


def test_view_typed_dict_keys_match_the_projection():
    view = analyze_function_view(AnalyzeFunctionResult(analysis=_analysis_fixture()))
    assert set(view.keys()) == set(AnalyzeFunctionView.__annotations__)


# -- catalog registration ---------------------------------------------------


def _register(
    use_case: AnalyzeFunctionUseCase, executor: _InlineExecutor
) -> Registry:
    registry = Registry()
    register_analyze_function(
        registry, analyze_function_use_case=use_case, executor=executor
    )
    return registry


def test_analyze_function_is_registered_read_only():
    use_case, _ = _default_scenario()
    registry = _register(use_case, _InlineExecutor())

    spec = registry.get_tool("analyze_function")
    assert spec is not None
    # A composite of read tools mutates nothing.
    assert spec.annotations["readOnlyHint"] is True
    assert "destructiveHint" not in spec.annotations


def test_tool_invocation_returns_the_wire_shape_through_the_executor():
    use_case, _ = _default_scenario()
    executor = _InlineExecutor()
    registry = _register(use_case, executor)

    view = registry.get_tool("analyze_function").invoke(address=hex(ENTRY))

    assert view["name"] == "process_data"
    assert view["profile"]["callee_count"] == 4
    assert view["import_references"] == ["malloc", "strcpy"]
    assert view["string_literals"] == ["hello %s", "/tmp/output"]
    # The whole composite ran on the kernel thread in exactly one marshalled job.
    assert len(executor.write_flags) == 1


def test_tool_invocation_surfaces_failure_as_a_tool_error():
    use_case, _ = _default_scenario()
    registry = _register(use_case, _InlineExecutor())

    # An address in no function becomes an isError result, not a protocol fault.
    with pytest.raises(ToolError):
        registry.get_tool("analyze_function").invoke(address="0x500000")
