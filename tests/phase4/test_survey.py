"""Unit tests for ``survey_binary`` — the one-call triage overview (no IDA).

Three layers are exercised entirely off-host:

* the pure :class:`SurveyService` — the authored function-role taxonomy
  (``thunk`` / ``library`` / ``small-leaf`` / ``leaf`` / ``hub`` / ``dispatcher``
  / ``large`` / ``ordinary``), the notable-import categoriser (with its fixed
  priority order), and the coarse string categoriser;
* the :class:`SurveyBinaryUseCase` — driven by fake read ports (functions,
  imports, strings, xrefs, database) so counts, entrypoints, truncation, the
  ``standard`` vs ``minimal`` classification split, the caller-/size-ranked
  shortlist, the notable-import filtering/cap, and the string summary are all
  asserted with no database; and
* the catalog projection and registration — the flat ``0x``-hex wire shape and
  the read-only tool wiring.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, TypeVar

import pytest

from idamesh.application.contexts.survey_binary import (
    DETAIL_MINIMAL,
    DETAIL_STANDARD,
    SURVEY_NOTABLE_IMPORTS,
    SURVEY_TOP_FUNCTIONS,
    SurveyBinaryUseCase,
)
from idamesh.application.dto.survey_binary import (
    SurveyBinaryCommand,
    SurveyBinaryResult,
)
from idamesh.domain.entities.function import Function
from idamesh.domain.entities.imports import Import
from idamesh.domain.entities.metadata import DatabaseMetadata, Endianness
from idamesh.domain.entities.string_item import StringItem
from idamesh.domain.entities.survey import (
    BinarySurvey,
    NotableFunction,
    NotableImport,
    RoleTally,
    StringCategoryTally,
    SurveyCounts,
)
from idamesh.domain.entities.xref import Xref, XrefKind, XrefType
from idamesh.domain.services.survey import (
    CATEGORY_ANTIDBG,
    CATEGORY_CRYPTO,
    CATEGORY_FILESYSTEM,
    CATEGORY_LOADER,
    CATEGORY_MEMORY,
    CATEGORY_NETWORK,
    CATEGORY_PROCESS,
    CATEGORY_REGISTRY,
    ROLE_DISPATCHER,
    ROLE_HUB,
    ROLE_LARGE,
    ROLE_LEAF,
    ROLE_LIBRARY,
    ROLE_ORDINARY,
    ROLE_SMALL_LEAF,
    ROLE_THUNK,
    STRING_COMMAND,
    STRING_FORMAT,
    STRING_IP,
    STRING_OTHER,
    STRING_PATH,
    STRING_REGISTRY,
    STRING_URL,
    SurveyService,
)
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import Page
from idamesh.interface.catalog.survey_binary import (
    register_survey_binary,
    survey_binary_view,
)
from idamesh.interface.catalog.views import metadata_view
from idamesh.interface.mcp.registry import Registry

T = TypeVar("T")


# -- fakes ------------------------------------------------------------------


class _FakeFunctions:
    """In-memory ``FunctionRepository`` returning a fixed page.

    ``total`` defaults to the page size; set it larger than the page to model a
    database whose function count exceeds the survey's bounded scan.
    """

    def __init__(self, funcs: List[Function], *, total: Optional[int] = None) -> None:
        self._funcs = list(funcs)
        self._total = len(self._funcs) if total is None else total

    def list(self, page) -> Page[Function]:
        return Page(
            items=list(self._funcs),
            offset=0,
            count=len(self._funcs),
            total=self._total,
        )

    def count(self) -> int:
        return self._total


class _FakeImports:
    """In-memory ``ImportRepository`` returning a fixed page."""

    def __init__(self, imports: List[Import], *, total: Optional[int] = None) -> None:
        self._imports = list(imports)
        self._total = len(self._imports) if total is None else total

    def list(self, page) -> Page[Import]:
        return Page(
            items=list(self._imports),
            offset=0,
            count=len(self._imports),
            total=self._total,
        )

    def count(self) -> int:
        return self._total


class _FakeStrings:
    """In-memory ``StringsRepository`` returning a fixed page."""

    def __init__(self, strings: List[StringItem], *, total: Optional[int] = None) -> None:
        self._strings = list(strings)
        self._total = len(self._strings) if total is None else total

    def list(self, page) -> Page[StringItem]:
        return Page(
            items=list(self._strings),
            offset=0,
            count=len(self._strings),
            total=self._total,
        )

    def count(self) -> int:
        return self._total


class _FakeXrefs:
    """In-memory ``XrefRepository`` returning planted call degrees per address.

    ``callers`` / ``callees`` map an integer EA to the number of inbound / outbound
    call edges the survey should see; the use-case only measures the *length* of
    each list. Every query is recorded so the ``minimal`` detail level can be
    asserted to skip the cross-reference scan entirely.
    """

    def __init__(
        self,
        callers: Optional[Dict[int, int]] = None,
        callees: Optional[Dict[int, int]] = None,
    ) -> None:
        self._callers = callers or {}
        self._callees = callees or {}
        self.refs_to_calls: List[int] = []
        self.callees_calls: List[int] = []

    def refs_to(self, ea: Address) -> List[Xref]:
        self.refs_to_calls.append(int(ea))
        return _edges(self._callers.get(int(ea), 0))

    def callees(self, ea: Address) -> List[Xref]:
        self.callees_calls.append(int(ea))
        return _edges(self._callees.get(int(ea), 0))


class _FakeDatabase:
    """In-memory ``DatabaseGateway`` yielding fixed metadata."""

    def __init__(self, metadata: DatabaseMetadata) -> None:
        self._metadata = metadata

    def metadata(self) -> DatabaseMetadata:
        return self._metadata


@dataclass
class _InlineExecutor:
    """A ``MainThreadExecutor`` that runs jobs inline, recording affinity."""

    write_flags: List[bool] = field(default_factory=list)

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        self.write_flags.append(write)
        return job()

    def on_kernel_thread(self) -> bool:
        return True


# -- helpers ----------------------------------------------------------------


def _edges(n: int) -> List[Xref]:
    """A list of ``n`` placeholder call edges (only its length is read)."""
    return [
        Xref(
            source=Address(0x1000 + i),
            target=Address(0x2000),
            kind=XrefKind.CODE,
            ref_type=XrefType.CALL,
        )
        for i in range(n)
    ]


def _func(
    ea: int = 0x401000,
    name: str = "f",
    size: int = 0x100,
    *,
    is_library: bool = False,
    is_thunk: bool = False,
) -> Function:
    return Function(
        ea=Address(ea),
        name=name,
        size=size,
        is_library=is_library,
        is_thunk=is_thunk,
    )


def _import(name: str, ea: int = 0x402000, module: str = "kernel32") -> Import:
    return Import(ea=Address(ea), name=name, module=module)


def _string(value: str, ea: int = 0x500000) -> StringItem:
    return StringItem(address=Address(ea), length=len(value), kind="C", value=value)


def _metadata(
    *, entrypoint: Optional[Address] = None, segment_count: int = 4
) -> DatabaseMetadata:
    return DatabaseMetadata(
        path="/tmp/sample.i64",
        module="sample.exe",
        architecture="metapc",
        bits=64,
        endianness=Endianness.LITTLE,
        entrypoint=entrypoint,
        segment_count=segment_count,
    )


def _use_case(
    *,
    functions: Optional[_FakeFunctions] = None,
    imports: Optional[_FakeImports] = None,
    strings: Optional[_FakeStrings] = None,
    xrefs: Optional[_FakeXrefs] = None,
    metadata: Optional[DatabaseMetadata] = None,
) -> SurveyBinaryUseCase:
    return SurveyBinaryUseCase(
        database=_FakeDatabase(metadata or _metadata()),
        functions=functions or _FakeFunctions([]),
        imports=imports or _FakeImports([]),
        strings=strings or _FakeStrings([]),
        xrefs=xrefs or _FakeXrefs(),
        survey=SurveyService(),
    )


# -- service: the function-role taxonomy ------------------------------------


def test_thunk_flag_wins_over_everything():
    service = SurveyService()
    # A large, heavily-called thunk is still a thunk — the flag dominates shape.
    role = service.classify_function(
        _func(size=0x800, is_thunk=True), caller_count=100, callee_count=100
    )
    assert role == ROLE_THUNK


def test_thunk_flag_beats_library_flag():
    service = SurveyService()
    role = service.classify_function(
        _func(is_thunk=True, is_library=True), caller_count=0, callee_count=0
    )
    assert role == ROLE_THUNK


def test_library_flag_wins_over_shape():
    service = SurveyService()
    role = service.classify_function(
        _func(size=0x2000, is_library=True), caller_count=1, callee_count=1
    )
    assert role == ROLE_LIBRARY


def test_zero_callees_small_body_is_small_leaf():
    service = SurveyService()
    # size == small_size (0x20) is on the small side of the boundary (<=).
    role = service.classify_function(
        _func(size=0x20), caller_count=0, callee_count=0
    )
    assert role == ROLE_SMALL_LEAF


def test_zero_callees_larger_body_is_leaf():
    service = SurveyService()
    role = service.classify_function(
        _func(size=0x21), caller_count=0, callee_count=0
    )
    assert role == ROLE_LEAF


def test_leaf_branch_precedes_hub_even_with_many_callers():
    service = SurveyService()
    # No callees ⇒ leaf, regardless of how many sites call it.
    role = service.classify_function(
        _func(size=0x100), caller_count=1000, callee_count=0
    )
    assert role == ROLE_LEAF


def test_many_callers_is_a_hub():
    service = SurveyService()
    role = service.classify_function(
        _func(size=0x100), caller_count=16, callee_count=1
    )
    assert role == ROLE_HUB


def test_hub_threshold_is_inclusive_and_below_is_not_a_hub():
    service = SurveyService()
    assert (
        service.classify_function(_func(), caller_count=15, callee_count=1)
        == ROLE_ORDINARY
    )
    assert (
        service.classify_function(_func(), caller_count=16, callee_count=1)
        == ROLE_HUB
    )


def test_high_fan_out_is_a_dispatcher():
    service = SurveyService()
    role = service.classify_function(
        _func(size=0x100), caller_count=0, callee_count=12
    )
    assert role == ROLE_DISPATCHER


def test_hub_beats_dispatcher_when_both_apply():
    service = SurveyService()
    # Many callers *and* many callees ⇒ hub takes priority.
    role = service.classify_function(
        _func(size=0x100), caller_count=16, callee_count=12
    )
    assert role == ROLE_HUB


def test_dispatcher_beats_large_body():
    service = SurveyService()
    role = service.classify_function(
        _func(size=0x2000), caller_count=0, callee_count=12
    )
    assert role == ROLE_DISPATCHER


def test_large_body_when_not_hub_or_dispatcher():
    service = SurveyService()
    role = service.classify_function(
        _func(size=0x400), caller_count=1, callee_count=1
    )
    assert role == ROLE_LARGE


def test_large_threshold_is_inclusive():
    service = SurveyService()
    assert (
        service.classify_function(_func(size=0x3FF), caller_count=1, callee_count=1)
        == ROLE_ORDINARY
    )
    assert (
        service.classify_function(_func(size=0x400), caller_count=1, callee_count=1)
        == ROLE_LARGE
    )


def test_middling_function_is_ordinary():
    service = SurveyService()
    role = service.classify_function(
        _func(size=0x100), caller_count=2, callee_count=3
    )
    assert role == ROLE_ORDINARY


# -- service: the cheap (flags + size only) classification ------------------


def test_classify_cheap_honours_flags():
    service = SurveyService()
    assert service.classify_cheap(_func(is_thunk=True)) == ROLE_THUNK
    assert service.classify_cheap(_func(is_library=True)) == ROLE_LIBRARY


def test_classify_cheap_uses_size_bands():
    service = SurveyService()
    assert service.classify_cheap(_func(size=0x10)) == ROLE_SMALL_LEAF
    assert service.classify_cheap(_func(size=0x20)) == ROLE_SMALL_LEAF
    assert service.classify_cheap(_func(size=0x400)) == ROLE_LARGE
    assert service.classify_cheap(_func(size=0x100)) == ROLE_ORDINARY


def test_classify_cheap_never_emits_degree_only_roles():
    service = SurveyService()
    # hub / dispatcher / leaf all require call-degree, which cheap never has.
    roles = {
        service.classify_cheap(_func(size=size))
        for size in (0x10, 0x40, 0x200, 0x800)
    }
    assert roles <= {ROLE_THUNK, ROLE_LIBRARY, ROLE_SMALL_LEAF, ROLE_LARGE, ROLE_ORDINARY}
    assert ROLE_HUB not in roles
    assert ROLE_DISPATCHER not in roles
    assert ROLE_LEAF not in roles


# -- service: the notable-import categoriser --------------------------------


@pytest.mark.parametrize(
    "name, expected",
    [
        ("IsDebuggerPresent", CATEGORY_ANTIDBG),
        ("CheckRemoteDebuggerPresent", CATEGORY_ANTIDBG),
        ("LoadLibraryA", CATEGORY_LOADER),
        ("GetProcAddress", CATEGORY_LOADER),
        ("CryptEncrypt", CATEGORY_CRYPTO),
        ("MD5Init", CATEGORY_CRYPTO),
        ("connect", CATEGORY_NETWORK),
        ("WSASocketW", CATEGORY_NETWORK),
        ("CreateProcessW", CATEGORY_PROCESS),
        ("ShellExecuteW", CATEGORY_PROCESS),
        ("CreateFileW", CATEGORY_FILESYSTEM),
        ("ReadFile", CATEGORY_FILESYSTEM),
        ("RegOpenKeyExW", CATEGORY_REGISTRY),
        ("VirtualAlloc", CATEGORY_MEMORY),
        ("memcpy", CATEGORY_MEMORY),
    ],
)
def test_categorize_import_maps_known_symbols(name, expected):
    assert SurveyService().categorize_import(name, "") == expected


@pytest.mark.parametrize("name", ["GetLastError", "lstrlenW", "printf"])
def test_categorize_import_returns_none_for_unremarkable(name):
    assert SurveyService().categorize_import(name, "") is None


def test_categorize_import_is_case_insensitive():
    service = SurveyService()
    assert service.categorize_import("CREATEFILEW", "") == CATEGORY_FILESYSTEM
    assert service.categorize_import("virtualalloc", "") == CATEGORY_MEMORY


def test_categorize_import_priority_loader_over_crypto():
    # Contains both "loadlibrary" (loader) and "crypt" (crypto); loader ranks first.
    assert SurveyService().categorize_import("LoadLibraryCrypt", "") == CATEGORY_LOADER


def test_categorize_import_priority_crypto_over_network():
    # Contains both "encrypt" (crypto) and "send" (network); crypto ranks first.
    assert SurveyService().categorize_import("EncryptAndSend", "") == CATEGORY_CRYPTO


def test_categorize_import_priority_antidebug_over_process():
    # Contains both "ntquery" (anti-debug) and "system" (process); anti-debug wins.
    assert (
        SurveyService().categorize_import("NtQuerySystemInformation", "")
        == CATEGORY_ANTIDBG
    )


# -- service: the string categoriser ----------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        ("https://c2.example/beacon", STRING_URL),
        ("http://host/path", STRING_URL),
        ("ftp://files/host", STRING_URL),
        ("cmd.exe /c whoami", STRING_COMMAND),
        ("powershell -enc AAAA", STRING_COMMAND),
        ("/bin/sh", STRING_COMMAND),
        ("HKEY_LOCAL_MACHINE\\Software\\X", STRING_REGISTRY),
        ("SOFTWARE\\Microsoft\\Windows", STRING_REGISTRY),
        ("Foo\\CurrentVersion\\Run", STRING_REGISTRY),
        ("%s failed with %d", STRING_FORMAT),
        ("192.168.1.1", STRING_IP),
        ("10.0.0.255", STRING_IP),
        ("256.256.256.256", STRING_OTHER),
        ("C:\\Users\\bob\\file.txt", STRING_PATH),
        ("kernel32.dll", STRING_PATH),
        ("/usr/bin/env", STRING_PATH),
        ("payload.exe", STRING_PATH),
        ("hello world", STRING_OTHER),
        ("just_a_token", STRING_OTHER),
    ],
)
def test_categorize_string_buckets(value, expected):
    assert SurveyService().categorize_string(value) == expected


def test_categorize_string_url_beats_command():
    # A URL that embeds cmd.exe is still classified by the earlier URL rule.
    assert SurveyService().categorize_string("http://host/cmd.exe") == STRING_URL


def test_categorize_string_registry_beats_path():
    # Registry keys look path-like (backslashes) but the registry rule runs first.
    assert (
        SurveyService().categorize_string("Software\\App\\config.dll")
        == STRING_REGISTRY
    )


def test_categorize_string_format_beats_path():
    assert SurveyService().categorize_string("C:\\temp\\%s.log") == STRING_FORMAT


# -- use-case: counts, metadata, entrypoints --------------------------------


def test_counts_and_metadata_are_aggregated():
    metadata = _metadata(entrypoint=Address(0x401000), segment_count=7)
    use_case = _use_case(
        functions=_FakeFunctions([_func()], total=3),
        imports=_FakeImports([_import("CreateFileW")], total=2),
        strings=_FakeStrings([_string("hello")], total=5),
        metadata=metadata,
    )

    survey = use_case.execute(SurveyBinaryCommand()).survey

    assert survey.metadata is metadata
    assert survey.counts == SurveyCounts(functions=3, imports=2, strings=5, segments=7)
    assert survey.detail_level == DETAIL_STANDARD


def test_entrypoint_included_when_present_and_dropped_when_absent():
    with_ep = _use_case(metadata=_metadata(entrypoint=Address(0x401000)))
    assert with_ep.execute(SurveyBinaryCommand()).survey.entrypoints == (
        Address(0x401000),
    )

    without_ep = _use_case(metadata=_metadata(entrypoint=None))
    assert without_ep.execute(SurveyBinaryCommand()).survey.entrypoints == ()


def test_truncated_when_total_exceeds_scanned():
    use_case = _use_case(functions=_FakeFunctions([_func(), _func(ea=0x402000)], total=100))
    survey = use_case.execute(SurveyBinaryCommand()).survey
    assert survey.scanned_functions == 2
    assert survey.truncated is True


def test_not_truncated_when_all_functions_scanned():
    use_case = _use_case(functions=_FakeFunctions([_func(), _func(ea=0x402000)]))
    survey = use_case.execute(SurveyBinaryCommand()).survey
    assert survey.scanned_functions == 2
    assert survey.truncated is False


def test_empty_database_yields_zeroed_survey():
    survey = _use_case().execute(SurveyBinaryCommand()).survey
    assert survey.counts == SurveyCounts(functions=0, imports=0, strings=0, segments=4)
    assert survey.scanned_functions == 0
    assert survey.truncated is False
    assert survey.roles == ()
    assert survey.notable_imports == ()
    assert survey.string_categories == ()
    assert survey.top_functions == ()
    assert survey.entrypoints == ()


# -- use-case: detail-level split -------------------------------------------


def test_unknown_detail_level_falls_back_to_standard():
    survey = _use_case().execute(SurveyBinaryCommand(detail_level="verbose")).survey
    assert survey.detail_level == DETAIL_STANDARD


def test_minimal_detail_skips_the_xref_scan():
    xrefs = _FakeXrefs(callers={0x401000: 50}, callees={0x401000: 50})
    use_case = _use_case(functions=_FakeFunctions([_func(size=0x100)]), xrefs=xrefs)

    survey = use_case.execute(SurveyBinaryCommand(detail_level=DETAIL_MINIMAL)).survey

    assert survey.detail_level == DETAIL_MINIMAL
    # No cross-reference queries were issued at all.
    assert xrefs.refs_to_calls == []
    assert xrefs.callees_calls == []
    # And the shortlist reports zero degree because it was never measured.
    assert survey.top_functions[0].caller_count == 0
    assert survey.top_functions[0].callee_count == 0


def test_standard_detail_measures_degree_via_xrefs():
    xrefs = _FakeXrefs(callers={0x401000: 20}, callees={0x401000: 3})
    use_case = _use_case(functions=_FakeFunctions([_func(size=0x100)]), xrefs=xrefs)

    survey = use_case.execute(SurveyBinaryCommand()).survey

    assert xrefs.refs_to_calls == [0x401000]
    assert xrefs.callees_calls == [0x401000]
    entry = survey.top_functions[0]
    assert entry.caller_count == 20
    assert entry.callee_count == 3
    assert entry.role == ROLE_HUB


def test_xref_lookup_failure_is_tolerated():
    class _BoomXrefs(_FakeXrefs):
        def refs_to(self, ea):
            raise RuntimeError("no graph")

        def callees(self, ea):
            raise LookupError("no graph")

    use_case = _use_case(functions=_FakeFunctions([_func(size=0x100)]), xrefs=_BoomXrefs())
    survey = use_case.execute(SurveyBinaryCommand()).survey
    # A degree query that blows up is treated as zero, not fatal.
    entry = survey.top_functions[0]
    assert entry.caller_count == 0
    assert entry.callee_count == 0
    assert entry.role == ROLE_LEAF  # zero callees ⇒ leaf


# -- use-case: role histogram -----------------------------------------------


def test_role_histogram_tallies_each_bucket():
    funcs = [
        _func(ea=0x1000, name="t1", is_thunk=True),
        _func(ea=0x1100, name="t2", is_thunk=True),
        _func(ea=0x1200, name="lib", is_library=True),
        _func(ea=0x1300, name="leaf", size=0x10),
        _func(ea=0x1400, name="ord", size=0x100),
    ]
    xrefs = _FakeXrefs(callers={0x1400: 1}, callees={0x1400: 2})
    use_case = _use_case(functions=_FakeFunctions(funcs), xrefs=xrefs)

    survey = use_case.execute(SurveyBinaryCommand()).survey

    tally = {t.role: t.count for t in survey.roles}
    assert tally == {ROLE_THUNK: 2, ROLE_LIBRARY: 1, ROLE_SMALL_LEAF: 1, ROLE_ORDINARY: 1}


def test_role_tally_is_sorted_by_count_descending():
    funcs = [_func(ea=0x1000 + i * 0x10, is_thunk=True) for i in range(3)]
    funcs.append(_func(ea=0x2000, name="ord", size=0x100))
    xrefs = _FakeXrefs(callees={0x2000: 2}, callers={0x2000: 1})
    survey = (
        _use_case(functions=_FakeFunctions(funcs), xrefs=xrefs)
        .execute(SurveyBinaryCommand())
        .survey
    )
    counts = [t.count for t in survey.roles]
    assert counts == sorted(counts, reverse=True)
    assert survey.roles[0].role == ROLE_THUNK  # the most populous bucket leads


# -- use-case: top-function shortlist ---------------------------------------


def test_top_functions_ranked_by_caller_count_in_standard():
    funcs = [
        _func(ea=0x1000, name="mid", size=0x100),
        _func(ea=0x1100, name="hot", size=0x100),
        _func(ea=0x1200, name="cold", size=0x100),
    ]
    xrefs = _FakeXrefs(
        callers={0x1000: 5, 0x1100: 20, 0x1200: 1},
        callees={0x1000: 1, 0x1100: 1, 0x1200: 1},
    )
    survey = (
        _use_case(functions=_FakeFunctions(funcs), xrefs=xrefs)
        .execute(SurveyBinaryCommand())
        .survey
    )
    assert [f.name for f in survey.top_functions] == ["hot", "mid", "cold"]


def test_top_functions_ranked_by_size_in_minimal():
    funcs = [
        _func(ea=0x1000, name="small", size=0x40),
        _func(ea=0x1100, name="big", size=0x800),
        _func(ea=0x1200, name="mid", size=0x100),
    ]
    survey = (
        _use_case(functions=_FakeFunctions(funcs))
        .execute(SurveyBinaryCommand(detail_level=DETAIL_MINIMAL))
        .survey
    )
    assert [f.name for f in survey.top_functions] == ["big", "mid", "small"]


def test_top_functions_shortlist_is_capped():
    funcs = [_func(ea=0x1000 + i * 0x10, name=f"f{i}", size=0x40 + i) for i in range(40)]
    survey = (
        _use_case(functions=_FakeFunctions(funcs))
        .execute(SurveyBinaryCommand(detail_level=DETAIL_MINIMAL))
        .survey
    )
    assert len(survey.top_functions) == SURVEY_TOP_FUNCTIONS
    # The kept entries are the largest ones — the smallest sizes are dropped.
    assert survey.top_functions[0].size == max(f.size for f in funcs)


# -- use-case: notable imports ----------------------------------------------


def test_notable_imports_keeps_only_categorised_in_order():
    imports = [
        _import("CryptEncrypt", ea=0x2000),
        _import("GetLastError", ea=0x2008),  # unremarkable — dropped
        _import("WSASocketW", ea=0x2010),
    ]
    survey = (
        _use_case(imports=_FakeImports(imports)).execute(SurveyBinaryCommand()).survey
    )
    assert survey.notable_imports == (
        NotableImport(
            name="CryptEncrypt",
            module="kernel32",
            address=Address(0x2000),
            category=CATEGORY_CRYPTO,
        ),
        NotableImport(
            name="WSASocketW",
            module="kernel32",
            address=Address(0x2010),
            category=CATEGORY_NETWORK,
        ),
    )


def test_notable_imports_shortlist_is_capped():
    imports = [
        _import("CryptEncrypt", ea=0x2000 + i * 8) for i in range(SURVEY_NOTABLE_IMPORTS + 5)
    ]
    survey = (
        _use_case(imports=_FakeImports(imports)).execute(SurveyBinaryCommand()).survey
    )
    assert len(survey.notable_imports) == SURVEY_NOTABLE_IMPORTS


# -- use-case: string category summary --------------------------------------


def test_string_category_summary_counts_and_sorts():
    strings = [
        _string("https://a", ea=0x5000),
        _string("http://b", ea=0x5010),
        _string("kernel32.dll", ea=0x5020),
        _string("C:\\a\\b.sys", ea=0x5030),
        _string("%s=%d", ea=0x5040),
        _string("plain text here", ea=0x5050),
        _string("SOFTWARE\\Key\\Value", ea=0x5060),
    ]
    survey = (
        _use_case(strings=_FakeStrings(strings)).execute(SurveyBinaryCommand()).survey
    )

    summary = {t.category: t.count for t in survey.string_categories}
    assert summary == {
        STRING_URL: 2,
        STRING_PATH: 2,
        STRING_FORMAT: 1,
        STRING_OTHER: 1,
        STRING_REGISTRY: 1,
    }
    # The tallies come back in non-increasing count order.
    counts = [t.count for t in survey.string_categories]
    assert counts == sorted(counts, reverse=True)


# -- view projection --------------------------------------------------------


def _sample_survey() -> BinarySurvey:
    return BinarySurvey(
        metadata=_metadata(entrypoint=Address(0x401000), segment_count=3),
        counts=SurveyCounts(functions=10, imports=4, strings=7, segments=3),
        detail_level=DETAIL_STANDARD,
        scanned_functions=10,
        truncated=True,
        entrypoints=(Address(0x401000), Address(0x401500)),
        roles=(RoleTally(role=ROLE_ORDINARY, count=6), RoleTally(role=ROLE_THUNK, count=4)),
        notable_imports=(
            NotableImport(
                name="CreateFileW",
                module="kernel32",
                address=Address(0x402000),
                category=CATEGORY_FILESYSTEM,
            ),
        ),
        string_categories=(StringCategoryTally(category=STRING_URL, count=3),),
        top_functions=(
            NotableFunction(
                address=Address(0x401000),
                name="main",
                size=0x120,
                role=ROLE_ORDINARY,
                caller_count=2,
                callee_count=5,
            ),
        ),
    )


def test_survey_binary_view_projects_flat_wire_shape():
    survey = _sample_survey()
    view = survey_binary_view(SurveyBinaryResult(survey=survey))

    assert view["metadata"] == metadata_view(survey.metadata)
    assert view["counts"] == {
        "functions": 10,
        "imports": 4,
        "strings": 7,
        "segments": 3,
    }
    assert view["detail_level"] == DETAIL_STANDARD
    assert view["scanned_functions"] == 10
    assert view["truncated"] is True
    assert view["entrypoints"] == ["0x401000", "0x401500"]
    assert view["roles"] == [
        {"role": ROLE_ORDINARY, "count": 6},
        {"role": ROLE_THUNK, "count": 4},
    ]
    assert view["notable_imports"] == [
        {
            "name": "CreateFileW",
            "module": "kernel32",
            "address": "0x402000",
            "category": CATEGORY_FILESYSTEM,
        }
    ]
    assert view["string_categories"] == [{"category": STRING_URL, "count": 3}]
    assert view["top_functions"] == [
        {
            "address": "0x401000",
            "name": "main",
            "size": 0x120,
            "role": ROLE_ORDINARY,
            "caller_count": 2,
            "callee_count": 5,
        }
    ]


def test_survey_binary_view_projects_empty_survey():
    survey = BinarySurvey(
        metadata=_metadata(),
        counts=SurveyCounts(functions=0, imports=0, strings=0, segments=4),
        detail_level=DETAIL_STANDARD,
        scanned_functions=0,
        truncated=False,
    )
    view = survey_binary_view(SurveyBinaryResult(survey=survey))
    assert view["entrypoints"] == []
    assert view["roles"] == []
    assert view["notable_imports"] == []
    assert view["string_categories"] == []
    assert view["top_functions"] == []


# -- catalog registration ---------------------------------------------------


def _register(use_case: SurveyBinaryUseCase, executor) -> Registry:
    registry = Registry()
    register_survey_binary(
        registry, survey_binary_use_case=use_case, executor=executor
    )
    return registry


def test_survey_binary_is_registered_read_only():
    registry = _register(_use_case(), _InlineExecutor())
    spec = registry.get_tool("survey_binary")
    assert spec is not None
    # A pure aggregation over read ports mutates nothing.
    assert spec.annotations["readOnlyHint"] is True
    assert "destructiveHint" not in spec.annotations


def test_survey_binary_tool_invocation_returns_wire_shape():
    use_case = _use_case(
        functions=_FakeFunctions([_func(size=0x100)], total=1),
        imports=_FakeImports([_import("CreateFileW")]),
        strings=_FakeStrings([_string("https://x")]),
        xrefs=_FakeXrefs(callers={0x401000: 2}, callees={0x401000: 3}),
        metadata=_metadata(entrypoint=Address(0x401000), segment_count=2),
    )
    executor = _InlineExecutor()
    registry = _register(use_case, executor)

    view = registry.get_tool("survey_binary").invoke(detail_level="standard")

    assert view["detail_level"] == "standard"
    assert view["counts"]["segments"] == 2
    assert view["entrypoints"] == ["0x401000"]
    assert view["notable_imports"][0]["category"] == CATEGORY_FILESYSTEM
    assert view["string_categories"][0]["category"] == STRING_URL
    assert view["top_functions"][0]["caller_count"] == 2
    # The aggregation ran through the executor exactly once.
    assert len(executor.write_flags) == 1
