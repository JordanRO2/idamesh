"""Unit tests for the ``find_dangerous_callers`` tool (no IDA).

Exercises the whole read path off-host: the pure
:class:`~idamesh.domain.services.dangerous_apis.DangerousApiService` classification
table (category / severity / name-decoration tolerance), the
:class:`~idamesh.application.contexts.find_dangerous_callers.FindDangerousCallersUseCase`
driven by fake import / xref / function repositories (caller aggregation grouped
under each dangerous import, enclosing-function attribution with a
``source_func`` -> ``get_containing`` fallback, benign imports ignored, empty
input, dangerous-but-uncalled import elided, multi-page walking, and
``limit`` / ``truncated`` clamping), the ``FindDangerousCallersView`` wire-shape
projection (addresses as ``0x`` hex, ``function`` nullable), and the registered
tool (default ``readOnlyHint: true`` and its marshalled invocation).
"""

from __future__ import annotations

from typing import Dict, List, Sequence

import pytest

from idamesh.application.contexts.find_dangerous_callers import (
    FindDangerousCallersUseCase,
)
from idamesh.application.dto.find_dangerous_callers import (
    DEFAULT_CALLER_LIMIT,
    MAX_CALLER_LIMIT,
    FindDangerousCallersCommand,
    FindDangerousCallersResult,
)
from idamesh.domain.entities.dangerous_caller import (
    DangerousApiMatch,
    DangerousCaller,
)
from idamesh.domain.entities.function import Function
from idamesh.domain.entities.imports import Import
from idamesh.domain.entities.xref import Xref, XrefKind, XrefType
from idamesh.domain.services.dangerous_apis import (
    CATEGORY_BUFFER_COPY,
    CATEGORY_COMMAND_EXEC,
    CATEGORY_FORMAT_STRING,
    CATEGORY_INPUT_PARSE,
    CATEGORY_MEMORY_MOVE,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    DangerousApi,
    DangerousApiService,
)
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import Page, PageRequest
from idamesh.infrastructure.execution.inline import InlineExecutor
from idamesh.interface.catalog.find_dangerous_callers import (
    dangerous_api_match_view,
    dangerous_caller_view,
    find_dangerous_callers_view,
    register_find_dangerous_callers,
)
from idamesh.interface.mcp.registry import Registry


# --------------------------------------------------------------------------- #
# Fakes: import / xref / function repositories (no IDA)
# --------------------------------------------------------------------------- #


class _FakeImportRepository:
    """In-memory import table that honours ``PageRequest`` offset/count."""

    def __init__(self, imports: Sequence[Import]) -> None:
        self._imports = list(imports)

    def list(self, page: PageRequest) -> Page[Import]:
        start = page.offset
        end = start + page.count
        window = self._imports[start:end]
        return Page(
            items=window,
            offset=start,
            count=page.count,
            total=len(self._imports),
            truncated=end < len(self._imports),
        )

    def count(self) -> int:
        return len(self._imports)


class _PagingImportRepository:
    """Import table that yields a fixed small page regardless of requested count.

    Ignores ``PageRequest.count`` and always returns at most ``page_size`` items,
    flagging ``truncated`` while more remain — forcing the use-case to walk
    several pages via its ``offset += len(items)`` continuation.
    """

    def __init__(self, imports: Sequence[Import], page_size: int = 2) -> None:
        self._imports = list(imports)
        self._page_size = page_size

    def list(self, page: PageRequest) -> Page[Import]:
        start = page.offset
        end = start + self._page_size
        window = self._imports[start:end]
        return Page(
            items=window,
            offset=start,
            count=self._page_size,
            total=len(self._imports),
            truncated=end < len(self._imports),
        )

    def count(self) -> int:
        return len(self._imports)


class _FakeXrefRepository:
    """Serves ``refs_to`` from a mapping of target-EA -> inbound edges."""

    def __init__(self, refs_by_ea: Dict[int, List[Xref]] | None = None) -> None:
        self._refs = dict(refs_by_ea or {})

    def refs_to(self, ea: Address) -> List[Xref]:
        return list(self._refs.get(int(ea), []))

    def callees(self, ea: Address) -> List[Xref]:  # pragma: no cover - unused here
        return []


class _FakeFunctionRepository:
    """Point-lookup fallback: maps an EA to its enclosing :class:`Function`."""

    def __init__(self, containing: Dict[int, Function] | None = None) -> None:
        self._containing = dict(containing or {})

    def get_containing(self, ea: Address) -> Function | None:
        return self._containing.get(int(ea))

    # Unused by the use-case, present to satisfy the port shape.
    def list(self, page: PageRequest) -> Page[Function]:  # pragma: no cover
        return Page(items=[], offset=page.offset, count=page.count, total=0)

    def count(self) -> int:  # pragma: no cover
        return 0

    def get(self, ea: Address) -> Function | None:  # pragma: no cover
        return None


def _call_xref(source: int, *, func: str | None) -> Xref:
    """A call edge from ``source`` into a dangerous import slot."""
    return Xref(
        source=Address(source),
        target=Address(0),
        kind=XrefKind.CODE,
        ref_type=XrefType.CALL,
        source_func=func,
    )


def _import(ea: int, name: str, module: str = "msvcrt.dll") -> Import:
    return Import(ea=Address(ea), name=name, module=module)


def _make_use_case(
    imports,
    xrefs,
    functions=None,
) -> FindDangerousCallersUseCase:
    return FindDangerousCallersUseCase(
        imports=imports,
        xrefs=xrefs,
        functions=functions if functions is not None else _FakeFunctionRepository(),
        danger=DangerousApiService(),
    )


# --------------------------------------------------------------------------- #
# Service: danger classification
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name, category, severity",
    [
        ("gets", CATEGORY_BUFFER_COPY, SEVERITY_CRITICAL),
        ("strcpy", CATEGORY_BUFFER_COPY, SEVERITY_HIGH),
        ("strcat", CATEGORY_BUFFER_COPY, SEVERITY_HIGH),
        ("sprintf", CATEGORY_BUFFER_COPY, SEVERITY_HIGH),
        ("strncpy", CATEGORY_BUFFER_COPY, SEVERITY_MEDIUM),
        ("memcpy", CATEGORY_MEMORY_MOVE, SEVERITY_MEDIUM),
        ("memmove", CATEGORY_MEMORY_MOVE, SEVERITY_MEDIUM),
        ("printf", CATEGORY_FORMAT_STRING, SEVERITY_HIGH),
        ("syslog", CATEGORY_FORMAT_STRING, SEVERITY_HIGH),
        ("scanf", CATEGORY_INPUT_PARSE, SEVERITY_MEDIUM),
        ("sscanf", CATEGORY_INPUT_PARSE, SEVERITY_MEDIUM),
        ("system", CATEGORY_COMMAND_EXEC, SEVERITY_HIGH),
        ("WinExec", CATEGORY_COMMAND_EXEC, SEVERITY_HIGH),
    ],
)
def test_service_classifies_known_apis(name, category, severity):
    api = DangerousApiService().classify(name)

    assert isinstance(api, DangerousApi)
    assert api.name == name
    assert api.category == category
    assert api.severity == severity


@pytest.mark.parametrize("name", ["strcpy", "gets", "system", "printf", "memcpy"])
def test_service_is_dangerous_true_for_known_apis(name):
    assert DangerousApiService().is_dangerous(name) is True


@pytest.mark.parametrize("name", ["malloc", "free", "strlen", "memcmp", "my_helper"])
def test_service_ignores_benign_names(name):
    service = DangerousApiService()
    assert service.classify(name) is None
    assert service.is_dangerous(name) is False


def test_service_strips_leading_underscore_decoration():
    # CRT imports frequently carry a single leading underscore (``_strcpy``).
    api = DangerousApiService().classify("_strcpy")
    assert api is not None
    assert api.name == "strcpy"


@pytest.mark.parametrize("decorated, canonical", [("lstrcpyA", "lstrcpy"), ("CreateProcessW", "CreateProcess")])
def test_service_strips_win32_charset_suffix(decorated, canonical):
    api = DangerousApiService().classify(decorated)
    assert api is not None
    assert api.name == canonical


@pytest.mark.parametrize("empty", ["", "   "])
def test_service_rejects_empty_name(empty):
    service = DangerousApiService()
    # A blank/whitespace-only name never classifies (exact miss, no bare token).
    assert service.classify(empty) is None or service.classify(empty.strip()) is None
    assert service.is_dangerous("") is False


def test_service_does_not_over_strip_single_character_name():
    # A bare ``"A"`` must not be mistaken for a suffix-stripped hit.
    assert DangerousApiService().classify("A") is None


# --------------------------------------------------------------------------- #
# Use-case: caller aggregation
# --------------------------------------------------------------------------- #


def test_use_case_groups_call_sites_under_each_dangerous_import():
    imports = _FakeImportRepository(
        [
            _import(0x1000, "strcpy"),
            _import(0x1008, "malloc"),  # benign — ignored
            _import(0x1010, "system"),
        ]
    )
    xrefs = _FakeXrefRepository(
        {
            0x1000: [
                _call_xref(0x401000, func="parse_header"),
                _call_xref(0x401040, func="parse_body"),
            ],
            0x1010: [_call_xref(0x402000, func="run_cmd")],
        }
    )
    use_case = _make_use_case(imports, xrefs)

    result = use_case.execute(FindDangerousCallersCommand())

    assert isinstance(result, FindDangerousCallersResult)
    assert result.truncated is False
    # First-seen order preserved: strcpy before system; malloc absent.
    assert [m.api for m in result.matches] == ["strcpy", "system"]

    strcpy_match = result.matches[0]
    assert strcpy_match == DangerousApiMatch(
        api="strcpy",
        callers=(
            DangerousCaller(address=Address(0x401000), function="parse_header"),
            DangerousCaller(address=Address(0x401040), function="parse_body"),
        ),
    )
    system_match = result.matches[1]
    assert system_match.callers == (
        DangerousCaller(address=Address(0x402000), function="run_cmd"),
    )


def test_use_case_ignores_only_benign_imports():
    imports = _FakeImportRepository(
        [_import(0x1000, "malloc"), _import(0x1008, "strlen")]
    )
    xrefs = _FakeXrefRepository({0x1000: [_call_xref(0x401000, func="f")]})
    use_case = _make_use_case(imports, xrefs)

    result = use_case.execute(FindDangerousCallersCommand())

    assert result.matches == ()
    assert result.truncated is False


def test_use_case_returns_empty_for_no_imports():
    use_case = _make_use_case(_FakeImportRepository([]), _FakeXrefRepository())

    result = use_case.execute(FindDangerousCallersCommand())

    assert result.matches == ()
    assert result.truncated is False


def test_use_case_elides_dangerous_import_with_no_call_sites():
    # ``gets`` is dangerous but never referenced -> it must not appear as an
    # empty-caller match.
    imports = _FakeImportRepository(
        [_import(0x1000, "gets"), _import(0x1008, "strcpy")]
    )
    xrefs = _FakeXrefRepository({0x1008: [_call_xref(0x401000, func="f")]})
    use_case = _make_use_case(imports, xrefs)

    result = use_case.execute(FindDangerousCallersCommand())

    assert [m.api for m in result.matches] == ["strcpy"]


def test_use_case_attributes_enclosing_function_via_containing_fallback():
    # The xref carries no ``source_func``; the enclosing name is recovered from
    # the function repository's point lookup.
    imports = _FakeImportRepository([_import(0x1000, "strcpy")])
    xrefs = _FakeXrefRepository({0x1000: [_call_xref(0x401000, func=None)]})
    functions = _FakeFunctionRepository(
        {0x401000: Function(ea=Address(0x400F00), name="decode", size=0x300)}
    )
    use_case = _make_use_case(imports, xrefs, functions)

    result = use_case.execute(FindDangerousCallersCommand())

    assert result.matches[0].callers[0] == DangerousCaller(
        address=Address(0x401000), function="decode"
    )


def test_use_case_reports_null_function_when_site_is_outside_any_function():
    imports = _FakeImportRepository([_import(0x1000, "strcpy")])
    xrefs = _FakeXrefRepository({0x1000: [_call_xref(0x401000, func=None)]})
    # Empty function repo -> get_containing returns None.
    use_case = _make_use_case(imports, xrefs, _FakeFunctionRepository())

    result = use_case.execute(FindDangerousCallersCommand())

    assert result.matches[0].callers[0].function is None


def test_use_case_prefers_source_func_over_containing_lookup():
    imports = _FakeImportRepository([_import(0x1000, "strcpy")])
    xrefs = _FakeXrefRepository({0x1000: [_call_xref(0x401000, func="edge_name")]})
    # The lookup would answer differently; the edge's own name must win.
    functions = _FakeFunctionRepository(
        {0x401000: Function(ea=Address(0x400F00), name="lookup_name", size=0x100)}
    )
    use_case = _make_use_case(imports, xrefs, functions)

    result = use_case.execute(FindDangerousCallersCommand())

    assert result.matches[0].callers[0].function == "edge_name"


def test_use_case_walks_multiple_import_pages():
    # Nine imports fed two at a time forces the paging continuation; the two
    # dangerous ones on different pages must both be collected.
    entries = [_import(0x1000 + 8 * i, f"benign_{i}") for i in range(9)]
    entries[2] = _import(0x1010, "strcpy")
    entries[7] = _import(0x1038, "system")
    imports = _PagingImportRepository(entries, page_size=2)
    xrefs = _FakeXrefRepository(
        {
            0x1010: [_call_xref(0x401000, func="a")],
            0x1038: [_call_xref(0x402000, func="b")],
        }
    )
    use_case = _make_use_case(imports, xrefs)

    result = use_case.execute(FindDangerousCallersCommand())

    assert {m.api for m in result.matches} == {"strcpy", "system"}
    assert result.truncated is False


# --------------------------------------------------------------------------- #
# Use-case: limit / truncation
# --------------------------------------------------------------------------- #


def test_use_case_truncates_when_limit_reached_within_one_import():
    imports = _FakeImportRepository([_import(0x1000, "strcpy")])
    xrefs = _FakeXrefRepository(
        {
            0x1000: [
                _call_xref(0x401000, func="f0"),
                _call_xref(0x401010, func="f1"),
                _call_xref(0x401020, func="f2"),
            ]
        }
    )
    use_case = _make_use_case(imports, xrefs)

    result = use_case.execute(FindDangerousCallersCommand(limit=2))

    assert result.truncated is True
    # Exactly the budget's worth of the earliest call sites, in order.
    assert result.matches[0].callers == (
        DangerousCaller(address=Address(0x401000), function="f0"),
        DangerousCaller(address=Address(0x401010), function="f1"),
    )


def test_use_case_limit_not_reached_is_not_truncated():
    imports = _FakeImportRepository([_import(0x1000, "strcpy")])
    xrefs = _FakeXrefRepository(
        {0x1000: [_call_xref(0x401000, func="f0"), _call_xref(0x401010, func="f1")]}
    )
    use_case = _make_use_case(imports, xrefs)

    result = use_case.execute(FindDangerousCallersCommand(limit=10))

    assert result.truncated is False
    assert len(result.matches[0].callers) == 2


def test_use_case_clamps_limit_to_maximum_without_error():
    imports = _FakeImportRepository([_import(0x1000, "strcpy")])
    xrefs = _FakeXrefRepository({0x1000: [_call_xref(0x401000, func="f0")]})
    use_case = _make_use_case(imports, xrefs)

    # A limit above the ceiling is clamped down; the single site still returns.
    result = use_case.execute(
        FindDangerousCallersCommand(limit=MAX_CALLER_LIMIT + 5000)
    )

    assert result.truncated is False
    assert len(result.matches[0].callers) == 1


def test_use_case_zero_limit_collects_nothing_but_flags_truncation():
    imports = _FakeImportRepository([_import(0x1000, "strcpy")])
    xrefs = _FakeXrefRepository({0x1000: [_call_xref(0x401000, func="f0")]})
    use_case = _make_use_case(imports, xrefs)

    result = use_case.execute(FindDangerousCallersCommand(limit=0))

    # No budget, yet dangerous work remained -> empty matches, truncated set.
    assert result.matches == ()
    assert result.truncated is True


def test_use_case_negative_limit_is_treated_as_zero():
    imports = _FakeImportRepository([_import(0x1000, "strcpy")])
    xrefs = _FakeXrefRepository({0x1000: [_call_xref(0x401000, func="f0")]})
    use_case = _make_use_case(imports, xrefs)

    result = use_case.execute(FindDangerousCallersCommand(limit=-3))

    assert result.matches == ()
    assert result.truncated is True


# --------------------------------------------------------------------------- #
# View projection
# --------------------------------------------------------------------------- #


def test_caller_view_renders_address_as_hex_and_keeps_function():
    view = dangerous_caller_view(
        DangerousCaller(address=Address(0x401000), function="parse")
    )
    assert view == {"address": "0x401000", "function": "parse"}


def test_caller_view_carries_null_function_through():
    view = dangerous_caller_view(
        DangerousCaller(address=Address(0x401000), function=None)
    )
    assert view == {"address": "0x401000", "function": None}


def test_match_view_nests_callers():
    view = dangerous_api_match_view(
        DangerousApiMatch(
            api="strcpy",
            callers=(
                DangerousCaller(address=Address(0x401000), function="a"),
                DangerousCaller(address=Address(0x401020), function=None),
            ),
        )
    )
    assert view == {
        "api": "strcpy",
        "callers": [
            {"address": "0x401000", "function": "a"},
            {"address": "0x401020", "function": None},
        ],
    }


def test_result_view_projects_full_wire_shape():
    result = FindDangerousCallersResult(
        matches=(
            DangerousApiMatch(
                api="system",
                callers=(
                    DangerousCaller(address=Address(0x14000A), function="run"),
                ),
            ),
        ),
        truncated=True,
    )
    view = find_dangerous_callers_view(result)

    assert view == {
        "matches": [
            {
                "api": "system",
                "callers": [{"address": "0x14000a", "function": "run"}],
            }
        ],
        "truncated": True,
    }


def test_result_view_of_empty_result():
    view = find_dangerous_callers_view(
        FindDangerousCallersResult(matches=(), truncated=False)
    )
    assert view == {"matches": [], "truncated": False}


# --------------------------------------------------------------------------- #
# Registered tool: annotations + invocation
# --------------------------------------------------------------------------- #


def _register(use_case: FindDangerousCallersUseCase) -> Registry:
    registry = Registry()
    register_find_dangerous_callers(
        registry,
        find_dangerous_callers_use_case=use_case,
        executor=InlineExecutor(),
    )
    return registry


def test_tool_is_advertised_read_only():
    use_case = _make_use_case(_FakeImportRepository([]), _FakeXrefRepository())
    spec = _register(use_case).get_tool("find_dangerous_callers")

    assert spec is not None
    # Registered via the default ``@registry.tool`` -> read-only advertisement.
    assert spec.annotations["readOnlyHint"] is True


def test_tool_default_limit_matches_dto():
    use_case = _make_use_case(_FakeImportRepository([]), _FakeXrefRepository())
    spec = _register(use_case).get_tool("find_dangerous_callers")

    # No positional args -> the DTO default is applied by the wired signature.
    assert spec.invoke() == {"matches": [], "truncated": False}
    assert DEFAULT_CALLER_LIMIT == 200


def test_tool_invocation_returns_projected_view():
    imports = _FakeImportRepository(
        [_import(0x1000, "strcpy"), _import(0x1010, "printf")]
    )
    xrefs = _FakeXrefRepository(
        {
            0x1000: [_call_xref(0x401000, func="copy_name")],
            0x1010: [_call_xref(0x402000, func=None)],
        }
    )
    spec = _register(_make_use_case(imports, xrefs)).get_tool(
        "find_dangerous_callers"
    )

    result = spec.invoke(limit=50)

    assert result == {
        "matches": [
            {
                "api": "strcpy",
                "callers": [{"address": "0x401000", "function": "copy_name"}],
            },
            {
                "api": "printf",
                "callers": [{"address": "0x402000", "function": None}],
            },
        ],
        "truncated": False,
    }
