"""Unit tests for the ``detect_vulns`` tool (no IDA).

Three layers are exercised entirely off-host:

* the pure :class:`VulnHeuristicsService`, driven on synthetic pseudocode so each
  authored rule (R1 unbounded copy, R2 format string, R3 command injection, R4
  unchecked memory move, R5 dangerous-API-reachable) fires on a crafted snippet
  and stays silent on safe code — including de-duplication, name normalization,
  and the finding's shape;
* the :class:`DetectVulnsUseCase`, with fake decompiler / function / xref / import
  gateways standing in for the IDA adapters, covering single-function scoping, the
  bounded whole-database sweep, per-function skip-on-decompile-failure, the scan
  bound, the empty result, and the resolution/availability failure paths;
* the ``DetectVulnsView`` projection and the registered tool — its read-only
  advertisement, its view marshalling, and its translation of a domain failure
  into a :class:`ToolError` (rendered as ``isError``).

The heuristics operate on already-fetched pseudocode text, so the whole suite runs
with no IDA present.
"""

from __future__ import annotations

from typing import Dict, List, Optional

import pytest

from idamesh.application.contexts.detect_vulns import (
    _MAX_FUNCTIONS,
    DetectVulnsUseCase,
)
from idamesh.application.dto.detect_vulns import (
    DetectVulnsCommand,
    DetectVulnsResult,
)
from idamesh.domain.entities.decompilation import Pseudocode
from idamesh.domain.entities.function import Function
from idamesh.domain.entities.imports import Import
from idamesh.domain.entities.vuln_finding import VulnFinding
from idamesh.domain.entities.xref import Xref, XrefKind, XrefType
from idamesh.domain.services.dangerous_apis import DangerousApiService
from idamesh.domain.services.vuln_heuristics import (
    KIND_BUFFER_OVERFLOW,
    KIND_COMMAND_INJECTION,
    KIND_DANGEROUS_CALL,
    KIND_FORMAT_STRING,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    VulnHeuristicsService,
)
from idamesh.domain.values.address import Address, Selector
from idamesh.domain.values.pagination import Page, PageRequest
from idamesh.infrastructure.execution.inline import InlineExecutor
from idamesh.interface.catalog.detect_vulns import (
    detect_vulns_view,
    register_detect_vulns,
    vuln_finding_view,
)
from idamesh.interface.mcp.engine import ToolError
from idamesh.interface.mcp.registry import Registry

_ENTRY = Address(0x401000)


def _analyze(code: str, *, function: Optional[str] = "f") -> List[VulnFinding]:
    """Run the heuristics over ``code`` with a fresh service and real classifier."""
    return VulnHeuristicsService().analyze(
        address=_ENTRY,
        function=function,
        pseudocode=code,
        danger=DangerousApiService(),
    )


def _kinds(findings: List[VulnFinding]) -> List[str]:
    return [f.kind for f in findings]


# --------------------------------------------------------------------------- #
# Heuristics — R1: unbounded string copy
# --------------------------------------------------------------------------- #


def test_r1_flags_strcpy_as_high_buffer_overflow():
    findings = _analyze("strcpy(dst, src);")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.kind == KIND_BUFFER_OVERFLOW
    assert finding.severity == SEVERITY_HIGH
    # The description names the rule and the sink so the finding is explainable.
    assert "R1" in finding.description
    assert "strcpy" in finding.description


def test_r1_flags_gets_as_critical_since_no_bound_is_possible():
    findings = _analyze("gets(buf);")

    assert len(findings) == 1
    assert findings[0].kind == KIND_BUFFER_OVERFLOW
    assert findings[0].severity == SEVERITY_CRITICAL
    assert "gets" in findings[0].description


@pytest.mark.parametrize("sink", ["strcat", "sprintf", "stpcpy", "wcscpy", "lstrcat"])
def test_r1_flags_the_whole_unbounded_copy_family(sink: str):
    findings = _analyze(f"{sink}(a, b);")

    assert _kinds(findings) == [KIND_BUFFER_OVERFLOW]
    assert "R1" in findings[0].description


def test_r1_fires_regardless_of_arguments():
    # R1 is a shape rule: the mere presence of the unbounded sink is the signal,
    # so even a call with a literal source is reported.
    assert _kinds(_analyze('strcpy(dst, "constant");')) == [KIND_BUFFER_OVERFLOW]


# --------------------------------------------------------------------------- #
# Heuristics — R2: format string
# --------------------------------------------------------------------------- #


def test_r2_flags_non_literal_format_argument():
    findings = _analyze("printf(user_supplied);")

    assert len(findings) == 1
    assert findings[0].kind == KIND_FORMAT_STRING
    assert findings[0].severity == SEVERITY_HIGH
    assert "R2" in findings[0].description


def test_r2_silent_when_format_is_a_string_literal():
    assert _analyze('printf("hello %d", n);') == []


def test_r2_silent_when_format_is_a_wide_string_literal():
    assert _analyze('printf(L"wide %s", s);') == []


def test_r2_uses_the_correct_format_index_for_fprintf():
    # fprintf's format is the *second* argument; a non-literal there fires.
    assert _kinds(_analyze("fprintf(stderr, fmt);")) == [KIND_FORMAT_STRING]
    # ... and a literal there stays silent.
    assert _analyze('fprintf(stderr, "ok\\n");') == []


# --------------------------------------------------------------------------- #
# Heuristics — R3: command injection
# --------------------------------------------------------------------------- #


def test_r3_flags_non_literal_command_argument():
    findings = _analyze("system(command);")

    assert len(findings) == 1
    assert findings[0].kind == KIND_COMMAND_INJECTION
    assert findings[0].severity == SEVERITY_HIGH
    assert "R3" in findings[0].description


def test_r3_silent_when_command_is_a_string_literal():
    assert _analyze('system("ls -la");') == []


@pytest.mark.parametrize("sink", ["popen", "execl", "execvp", "WinExec"])
def test_r3_covers_the_command_launcher_family(sink: str):
    assert _kinds(_analyze(f"{sink}(cmd, mode);")) == [KIND_COMMAND_INJECTION]


# --------------------------------------------------------------------------- #
# Heuristics — R4: unchecked memory move
# --------------------------------------------------------------------------- #


def test_r4_flags_non_constant_size():
    findings = _analyze("memcpy(dst, src, len);")

    assert len(findings) == 1
    assert findings[0].kind == KIND_BUFFER_OVERFLOW
    assert findings[0].severity == SEVERITY_MEDIUM
    assert "R4" in findings[0].description


@pytest.mark.parametrize("size", ["16", "0x20", "sizeof(buf)", "128u"])
def test_r4_silent_when_size_is_a_compile_time_constant(size: str):
    assert _analyze(f"memcpy(dst, src, {size});") == []


def test_r4_covers_memmove():
    assert _kinds(_analyze("memmove(a, b, n);")) == [KIND_BUFFER_OVERFLOW]


# --------------------------------------------------------------------------- #
# Heuristics — R5: dangerous API reachable (fallback signpost)
# --------------------------------------------------------------------------- #


def test_r5_flags_a_dangerous_api_that_tripped_no_specific_rule():
    # scanf is dangerous (input parsing) but matches none of R1-R4, so it falls
    # through to the low-severity reachability signpost.
    findings = _analyze('scanf("%s", buf);')

    assert len(findings) == 1
    assert findings[0].kind == KIND_DANGEROUS_CALL
    assert findings[0].severity == SEVERITY_LOW
    assert "R5" in findings[0].description
    assert "scanf" in findings[0].description


def test_r5_reports_the_bounded_copy_variants():
    # strncpy is classified dangerous but bounded, so it is an R5 signpost only.
    assert _kinds(_analyze("strncpy(dst, src, n);")) == [KIND_DANGEROUS_CALL]


def test_r5_does_not_double_report_when_a_specific_rule_already_fired():
    # strcpy trips R1 and must NOT also surface as an R5 dangerous_call.
    findings = _analyze("strcpy(dst, src);")

    assert _kinds(findings) == [KIND_BUFFER_OVERFLOW]


# --------------------------------------------------------------------------- #
# Heuristics — safe code, de-duplication, normalization, combinations
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "safe",
    [
        "int x = a + b; return x;",
        "result = helper(value);",  # helper is not a dangerous API
        "for (i = 0; i < n; i++) total += data[i];",
        "",  # empty pseudocode
    ],
)
def test_no_findings_on_safe_pseudocode(safe: str):
    assert _analyze(safe) == []


def test_same_sink_called_twice_reports_once():
    findings = _analyze("strcpy(a, b); strcpy(c, d);")

    assert len(findings) == 1


def test_distinct_sinks_report_separately():
    findings = _analyze("strcpy(a, b); strcat(c, d);")

    assert len(findings) == 2
    assert all(f.kind == KIND_BUFFER_OVERFLOW for f in findings)
    # Both distinct sinks are named across the two descriptions.
    joined = " ".join(f.description for f in findings)
    assert "strcpy" in joined and "strcat" in joined


def test_leading_underscore_is_normalized_before_matching():
    assert _kinds(_analyze("_strcpy(dst, src);")) == [KIND_BUFFER_OVERFLOW]


def test_win32_charset_suffix_is_normalized_before_matching():
    assert _kinds(_analyze("lstrcpyA(dst, src);")) == [KIND_BUFFER_OVERFLOW]


def test_multiple_rules_fire_together_in_one_function():
    code = "strcpy(dst, src); printf(fmt); system(cmd); memcpy(a, b, n);"

    kinds = set(_kinds(_analyze(code)))

    assert kinds == {
        KIND_BUFFER_OVERFLOW,
        KIND_FORMAT_STRING,
        KIND_COMMAND_INJECTION,
    }


def test_truncated_call_does_not_fire_a_rule_needing_an_argument():
    # An unbalanced call has no parseable argument list, so R3 cannot judge the
    # command argument and stays silent rather than guessing.
    assert _analyze("system(cmd") == []


# --------------------------------------------------------------------------- #
# Heuristics — finding shape
# --------------------------------------------------------------------------- #


def test_finding_is_anchored_at_the_supplied_address_and_function():
    findings = _analyze("gets(buf);", function="parse_input")

    finding = findings[0]
    assert isinstance(finding, VulnFinding)
    assert finding.address == _ENTRY
    assert finding.function == "parse_input"
    assert isinstance(finding.kind, str) and finding.kind
    assert isinstance(finding.severity, str) and finding.severity
    assert isinstance(finding.description, str) and finding.description


def test_finding_carries_a_none_function_through():
    findings = _analyze("gets(buf);", function=None)

    assert findings[0].function is None


# --------------------------------------------------------------------------- #
# Fakes for the use-case
# --------------------------------------------------------------------------- #


class _FakeDatabase:
    """A resolver-backed database gateway over a fixed symbol table."""

    def __init__(self, symbols: Optional[Dict[str, int]] = None) -> None:
        self._symbols = symbols or {}

    def resolve_symbol(self, name: str) -> Optional[int]:
        return self._symbols.get(name)

    def resolve(self, selector: Selector) -> Address:
        return selector.resolve(self)


class _FakeDecompiler:
    """An in-memory decompiler mapping EA -> pseudocode, with failure control.

    ``sources`` maps a function entry EA to its pseudocode text. ``available``
    models the licensing check the whole-database scan gates on. ``fail`` is the
    set of EAs whose decompilation raises, used to prove a swept function is
    skipped while a scoped one propagates.
    """

    def __init__(
        self,
        sources: Optional[Dict[int, str]] = None,
        *,
        available: bool = True,
        fail: Optional[set] = None,
    ) -> None:
        self._sources = sources or {}
        self._available = available
        self._fail = fail or set()
        self.decompiled: List[int] = []

    def is_available(self) -> bool:
        return self._available

    def decompile(self, ea: Address) -> Pseudocode:
        self.decompiled.append(int(ea))
        if int(ea) in self._fail:
            raise RuntimeError(f"decompilation failed at {ea.hex()}")
        text = self._sources.get(int(ea))
        if text is None:
            raise ValueError(f"no function at {ea.hex()}")
        return Pseudocode(ea=ea, text=text, lines=tuple(text.splitlines()))


class _FakeFunctions:
    """A function repository resolving ``get_containing`` from a fixed map."""

    def __init__(self, containing: Optional[Dict[int, Function]] = None) -> None:
        self._containing = containing or {}
        self.get_containing_seen: List[int] = []

    def get_containing(self, ea: Address) -> Optional[Function]:
        self.get_containing_seen.append(int(ea))
        return self._containing.get(int(ea))


class _FakeXrefs:
    """An xref repository over a fixed ``refs_to`` map."""

    def __init__(self, refs: Optional[Dict[int, List[Xref]]] = None) -> None:
        self._refs = refs or {}

    def refs_to(self, ea: Address) -> List[Xref]:
        return list(self._refs.get(int(ea), []))

    def callees(self, ea: Address) -> List[Xref]:  # unused by this use-case
        return []


class _FakeImports:
    """An import repository serving a single page of a fixed import list."""

    def __init__(self, imports: Optional[List[Import]] = None) -> None:
        self._imports = imports or []

    def list(self, page: PageRequest) -> Page[Import]:
        # The whole set lives on the first page; later offsets are empty. The
        # use-case stops after a non-truncated short page, so offset never grows.
        items = self._imports if page.offset == 0 else []
        return Page(
            items=list(items),
            offset=page.offset,
            count=page.count,
            total=len(self._imports),
            truncated=False,
        )

    def count(self) -> int:
        return len(self._imports)


def _ref(source: int) -> Xref:
    return Xref(
        source=Address(source),
        target=Address(0x500000),
        kind=XrefKind.CODE,
        ref_type=XrefType.CALL,
    )


def _import(name: str, ea: int) -> Import:
    return Import(ea=Address(ea), name=name, module="libc.so")


def _make_use_case(
    *,
    decompiler: _FakeDecompiler,
    functions: _FakeFunctions,
    xrefs: Optional[_FakeXrefs] = None,
    imports: Optional[_FakeImports] = None,
    database: Optional[_FakeDatabase] = None,
) -> DetectVulnsUseCase:
    return DetectVulnsUseCase(
        decompiler=decompiler,
        functions=functions,
        xrefs=xrefs or _FakeXrefs(),
        imports=imports or _FakeImports(),
        danger=DangerousApiService(),
        heuristics=VulnHeuristicsService(),
        database=database or _FakeDatabase(),
    )


# --------------------------------------------------------------------------- #
# Use-case — single-function (scoped) mode
# --------------------------------------------------------------------------- #


def test_scoped_scan_reports_findings_for_the_containing_function():
    func = Function(ea=_ENTRY, name="parse", size=0x40)
    decompiler = _FakeDecompiler({0x401000: "gets(buf);"})
    functions = _FakeFunctions({0x401000: func})
    use_case = _make_use_case(decompiler=decompiler, functions=functions)

    result = use_case.execute(DetectVulnsCommand(address="0x401000"))

    assert isinstance(result, DetectVulnsResult)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.address == _ENTRY
    assert finding.function == "parse"
    assert finding.kind == KIND_BUFFER_OVERFLOW
    # Only the scoped function was decompiled.
    assert decompiler.decompiled == [0x401000]


def test_scoped_scan_resolves_an_address_inside_the_function_body():
    func = Function(ea=_ENTRY, name="victim", size=0x40)
    decompiler = _FakeDecompiler({0x401000: "system(cmd);"})
    # The queried address is inside the body; get_containing maps it to the entry.
    functions = _FakeFunctions({0x401010: func})
    use_case = _make_use_case(decompiler=decompiler, functions=functions)

    result = use_case.execute(DetectVulnsCommand(address="0x401010"))

    assert [f.kind for f in result.findings] == [KIND_COMMAND_INJECTION]
    # The finding is anchored at the function entry, not the queried address.
    assert result.findings[0].address == _ENTRY


def test_scoped_scan_resolves_a_symbol_selector():
    func = Function(ea=_ENTRY, name="handler", size=0x40)
    decompiler = _FakeDecompiler({0x401000: "printf(fmt);"})
    functions = _FakeFunctions({0x401000: func})
    database = _FakeDatabase(symbols={"handler": 0x401000})
    use_case = _make_use_case(
        decompiler=decompiler, functions=functions, database=database
    )

    result = use_case.execute(DetectVulnsCommand(address="handler"))

    assert [f.kind for f in result.findings] == [KIND_FORMAT_STRING]


def test_scoped_scan_on_safe_function_returns_no_findings():
    func = Function(ea=_ENTRY, name="clean", size=0x40)
    decompiler = _FakeDecompiler({0x401000: "return a + b;"})
    functions = _FakeFunctions({0x401000: func})
    use_case = _make_use_case(decompiler=decompiler, functions=functions)

    result = use_case.execute(DetectVulnsCommand(address="0x401000"))

    assert result.findings == ()


def test_scoped_address_in_no_function_raises():
    decompiler = _FakeDecompiler({})
    functions = _FakeFunctions({})  # get_containing returns None
    use_case = _make_use_case(decompiler=decompiler, functions=functions)

    with pytest.raises(ValueError):
        use_case.execute(DetectVulnsCommand(address="0x401000"))
    # Resolution failed before any decompile.
    assert decompiler.decompiled == []


def test_scoped_unresolvable_symbol_raises():
    decompiler = _FakeDecompiler({})
    functions = _FakeFunctions({})
    use_case = _make_use_case(decompiler=decompiler, functions=functions)

    with pytest.raises(ValueError):
        use_case.execute(DetectVulnsCommand(address="ghost_symbol"))


def test_scoped_decompiler_failure_propagates():
    func = Function(ea=_ENTRY, name="stubborn", size=0x40)
    decompiler = _FakeDecompiler({}, fail={0x401000})
    functions = _FakeFunctions({0x401000: func})
    use_case = _make_use_case(decompiler=decompiler, functions=functions)

    # In scoped mode a decompile failure is not swallowed — it surfaces.
    with pytest.raises(RuntimeError):
        use_case.execute(DetectVulnsCommand(address="0x401000"))


# --------------------------------------------------------------------------- #
# Use-case — whole-database (bounded) mode
# --------------------------------------------------------------------------- #


def test_whole_db_scan_analyzes_only_functions_reaching_a_dangerous_api():
    victim = Function(ea=_ENTRY, name="victim", size=0x40)
    decompiler = _FakeDecompiler({0x401000: "strcpy(dst, src);"})
    functions = _FakeFunctions({0x401010: victim})
    # strcpy is dangerous; malloc is not. Only strcpy's caller is swept.
    imports = _FakeImports([_import("strcpy", 0x500000), _import("malloc", 0x500008)])
    xrefs = _FakeXrefs({0x500000: [_ref(0x401010)]})
    use_case = _make_use_case(
        decompiler=decompiler, functions=functions, xrefs=xrefs, imports=imports
    )

    result = use_case.execute(DetectVulnsCommand(address=""))

    assert [f.function for f in result.findings] == ["victim"]
    assert [f.kind for f in result.findings] == [KIND_BUFFER_OVERFLOW]
    # Only the dangerous import's caller was decompiled; malloc contributed none.
    assert decompiler.decompiled == [0x401000]


def test_whole_db_scan_skips_a_function_whose_decompilation_fails():
    good = Function(ea=Address(0x401000), name="good", size=0x40)
    bad = Function(ea=Address(0x402000), name="bad", size=0x40)
    decompiler = _FakeDecompiler(
        {0x401000: "gets(buf);"}, fail={0x402000}
    )
    functions = _FakeFunctions({0x401010: good, 0x402010: bad})
    imports = _FakeImports([_import("gets", 0x500000)])
    xrefs = _FakeXrefs({0x500000: [_ref(0x401010), _ref(0x402010)]})
    use_case = _make_use_case(
        decompiler=decompiler, functions=functions, xrefs=xrefs, imports=imports
    )

    result = use_case.execute(DetectVulnsCommand(address=""))

    # The failing function is skipped, not fatal; the good one still reports.
    assert [f.function for f in result.findings] == ["good"]
    assert set(decompiler.decompiled) == {0x401000, 0x402000}


def test_whole_db_scan_with_no_dangerous_imports_is_empty():
    decompiler = _FakeDecompiler({0x401000: "strcpy(a, b);"})
    functions = _FakeFunctions({0x401010: Function(ea=_ENTRY, name="x", size=0x10)})
    imports = _FakeImports([_import("malloc", 0x500000), _import("free", 0x500008)])
    xrefs = _FakeXrefs({0x500000: [_ref(0x401010)]})
    use_case = _make_use_case(
        decompiler=decompiler, functions=functions, xrefs=xrefs, imports=imports
    )

    result = use_case.execute(DetectVulnsCommand(address=""))

    assert result.findings == ()
    # No dangerous import ⇒ nothing decompiled.
    assert decompiler.decompiled == []


def test_whole_db_scan_requires_an_available_decompiler():
    decompiler = _FakeDecompiler({}, available=False)
    functions = _FakeFunctions({})
    use_case = _make_use_case(decompiler=decompiler, functions=functions)

    with pytest.raises(RuntimeError):
        use_case.execute(DetectVulnsCommand(address=""))
    assert decompiler.decompiled == []


def test_whole_db_scan_dedupes_functions_reached_via_two_dangerous_imports():
    victim = Function(ea=_ENTRY, name="victim", size=0x40)
    decompiler = _FakeDecompiler({0x401000: "strcpy(a, b); system(cmd);"})
    functions = _FakeFunctions({0x401010: victim, 0x401020: victim})
    imports = _FakeImports([_import("strcpy", 0x500000), _import("system", 0x500008)])
    xrefs = _FakeXrefs(
        {0x500000: [_ref(0x401010)], 0x500008: [_ref(0x401020)]}
    )
    use_case = _make_use_case(
        decompiler=decompiler, functions=functions, xrefs=xrefs, imports=imports
    )

    result = use_case.execute(DetectVulnsCommand(address=""))

    # The function is reached through both imports but decompiled/analyzed once.
    assert decompiler.decompiled == [0x401000]
    assert {f.kind for f in result.findings} == {
        KIND_BUFFER_OVERFLOW,
        KIND_COMMAND_INJECTION,
    }


def test_whole_db_scan_is_bounded_to_max_functions():
    # More dangerous callers than the cap: the sweep must stop at _MAX_FUNCTIONS.
    over = _MAX_FUNCTIONS + 5
    entries = [0x401000 + i * 0x100 for i in range(over)]
    containing = {ea: Function(ea=Address(ea), name=f"f{ea:x}", size=0x40) for ea in entries}
    sources = {ea: "gets(buf);" for ea in entries}
    decompiler = _FakeDecompiler(sources)
    functions = _FakeFunctions(containing)
    imports = _FakeImports([_import("gets", 0x500000)])
    xrefs = _FakeXrefs({0x500000: [_ref(ea) for ea in entries]})
    use_case = _make_use_case(
        decompiler=decompiler, functions=functions, xrefs=xrefs, imports=imports
    )

    result = use_case.execute(DetectVulnsCommand(address=""))

    # Exactly the cap's worth of functions were swept — never the whole overflow.
    assert len(decompiler.decompiled) == _MAX_FUNCTIONS
    assert len(result.findings) == _MAX_FUNCTIONS


# --------------------------------------------------------------------------- #
# View projection
# --------------------------------------------------------------------------- #


def test_vuln_finding_view_projects_to_flat_wire_shape():
    view = vuln_finding_view(
        VulnFinding(
            address=Address(0x401000),
            function="parse",
            kind=KIND_BUFFER_OVERFLOW,
            severity=SEVERITY_HIGH,
            description="R1 unbounded copy: strcpy()",
        )
    )

    assert view == {
        "address": "0x401000",
        "function": "parse",
        "kind": KIND_BUFFER_OVERFLOW,
        "severity": SEVERITY_HIGH,
        "description": "R1 unbounded copy: strcpy()",
    }


def test_vuln_finding_view_carries_a_null_function_through():
    view = vuln_finding_view(
        VulnFinding(
            address=Address(0x14000A),
            function=None,
            kind=KIND_DANGEROUS_CALL,
            severity=SEVERITY_LOW,
            description="R5",
        )
    )

    assert view["function"] is None
    assert view["address"] == "0x14000a"


def test_detect_vulns_view_projects_every_finding():
    result = DetectVulnsResult(
        findings=(
            VulnFinding(
                address=Address(0x401000),
                function="a",
                kind=KIND_BUFFER_OVERFLOW,
                severity=SEVERITY_HIGH,
                description="R1",
            ),
            VulnFinding(
                address=Address(0x402000),
                function="b",
                kind=KIND_FORMAT_STRING,
                severity=SEVERITY_HIGH,
                description="R2",
            ),
        )
    )

    view = detect_vulns_view(result)

    assert [f["address"] for f in view["findings"]] == ["0x401000", "0x402000"]
    assert [f["kind"] for f in view["findings"]] == [
        KIND_BUFFER_OVERFLOW,
        KIND_FORMAT_STRING,
    ]


def test_detect_vulns_view_of_empty_result():
    assert detect_vulns_view(DetectVulnsResult(findings=())) == {"findings": []}


# --------------------------------------------------------------------------- #
# Registered tool — advertisement, invocation, error translation
# --------------------------------------------------------------------------- #


def _register(use_case: DetectVulnsUseCase) -> Registry:
    registry = Registry()
    register_detect_vulns(
        registry, detect_vulns_use_case=use_case, executor=InlineExecutor()
    )
    return registry


def test_tool_is_advertised_read_only():
    func = Function(ea=_ENTRY, name="f", size=0x40)
    use_case = _make_use_case(
        decompiler=_FakeDecompiler({0x401000: ""}),
        functions=_FakeFunctions({0x401000: func}),
    )
    spec = _register(use_case).get_tool("detect_vulns")

    assert spec is not None
    # An unmarked analytics tool defaults to the read-only advertisement.
    assert spec.annotations["readOnlyHint"] is True
    assert "destructiveHint" not in spec.annotations


def test_tool_invocation_returns_the_view():
    func = Function(ea=_ENTRY, name="parse", size=0x40)
    use_case = _make_use_case(
        decompiler=_FakeDecompiler({0x401000: "gets(buf);"}),
        functions=_FakeFunctions({0x401000: func}),
    )
    spec = _register(use_case).get_tool("detect_vulns")

    view = spec.invoke(address="0x401000")

    assert view == {
        "findings": [
            {
                "address": "0x401000",
                "function": "parse",
                "kind": KIND_BUFFER_OVERFLOW,
                "severity": SEVERITY_CRITICAL,
                "description": view["findings"][0]["description"],
            }
        ]
    }
    assert "R1" in view["findings"][0]["description"]


def test_tool_invocation_on_safe_function_returns_empty_findings():
    func = Function(ea=_ENTRY, name="clean", size=0x40)
    use_case = _make_use_case(
        decompiler=_FakeDecompiler({0x401000: "return 0;"}),
        functions=_FakeFunctions({0x401000: func}),
    )
    spec = _register(use_case).get_tool("detect_vulns")

    assert spec.invoke(address="0x401000") == {"findings": []}


def test_tool_invocation_surfaces_out_of_function_address_as_tool_error():
    use_case = _make_use_case(
        decompiler=_FakeDecompiler({}), functions=_FakeFunctions({})
    )
    spec = _register(use_case).get_tool("detect_vulns")

    with pytest.raises(ToolError):
        spec.invoke(address="0x401000")


def test_tool_invocation_surfaces_unavailable_decompiler_as_tool_error():
    # Whole-database mode with no decompiler licensed becomes a clean isError.
    use_case = _make_use_case(
        decompiler=_FakeDecompiler({}, available=False),
        functions=_FakeFunctions({}),
    )
    spec = _register(use_case).get_tool("detect_vulns")

    with pytest.raises(ToolError):
        spec.invoke(address="")
