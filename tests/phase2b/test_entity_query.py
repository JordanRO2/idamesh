"""Unit tests for the ``entity_query`` use-case, shared query model, and view.

``entity_query`` is the unified named-entity read tool: it draws from the
function, named-global, and import repositories (selected by ``kind``), filters
each entity's name with the shared pure predicate grammar, and returns one flat,
bounded, ``truncated``-flagged stream. In-memory fakes stand in for the three IDA
adapters so the whole module — the kind selection, the case-insensitive name
filter, the limit/clamp/truncation contract, cross-page enumeration, the
projection to :class:`NamedEntity`, and the wire view — is exercised with no IDA
present. The shared :mod:`idamesh.domain.query.predicate` grammar it reuses is
guarded here as well, since it is total, IDA-free, and authored for these tools.
"""

from __future__ import annotations

from typing import List, Optional

from idamesh.application.contexts.entity_query import EntityQueryUseCase
from idamesh.application.dto.entity_query import (
    ENTITY_KINDS,
    MAX_ENTITY_QUERY_LIMIT,
    EntityQueryCommand,
    EntityQueryResult,
)
from idamesh.domain.entities.data import Global
from idamesh.domain.entities.function import Function
from idamesh.domain.entities.imports import Import
from idamesh.domain.entities.named_entity import (
    KIND_FUNCTION,
    KIND_GLOBAL,
    KIND_IMPORT,
    NamedEntity,
)
from idamesh.domain.query.predicate import FieldOp, FieldPredicate, Query
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import MAX_COUNT, Page, PageRequest
from idamesh.interface.catalog.entity_query import (
    entity_match_view,
    entity_query_view,
)

import pytest


# -- fakes ----------------------------------------------------------------


class _FakePagedRepository:
    """A paginated repository over a fixed, address-ordered list of items.

    Mirrors the paging contract the IDA adapters honour: a window slice, an
    exact ``total``, and a ``truncated`` flag set when the requested slice does
    not reach the end. Records every :class:`PageRequest` so tests can assert
    the cross-page walk and that unselected repositories are never touched.
    """

    def __init__(self, items: List[object]) -> None:
        self._items = items
        self.requests: List[PageRequest] = []

    def list(self, page: PageRequest) -> Page:
        self.requests.append(page)
        start = page.offset
        stop = start + page.count
        window = self._items[start:stop]
        return Page(
            items=window,
            offset=start,
            count=page.count,
            total=len(self._items),
            truncated=stop < len(self._items),
        )

    def count(self) -> int:
        return len(self._items)


class _FakeFunctionRepository(_FakePagedRepository):
    """A ``FunctionRepository`` fake; ``get*`` are unused by ``entity_query``."""

    def get(self, ea: Address) -> Optional[Function]:  # pragma: no cover - unused
        return None

    def get_containing(
        self, ea: Address
    ) -> Optional[Function]:  # pragma: no cover - unused
        return None


class _FakeGlobalRepository(_FakePagedRepository):
    """A ``GlobalRepository`` fake."""


class _FakeImportRepository(_FakePagedRepository):
    """An ``ImportRepository`` fake."""


# -- builders -------------------------------------------------------------


def _func(addr: int, name: str, size: int = 0x20) -> Function:
    return Function(ea=Address(addr), name=name, size=size)


def _glob(addr: int, name: str, size: int = 0x8) -> Global:
    return Global(ea=Address(addr), name=name, size=size)


def _imp(
    addr: int, name: str, module: str, ordinal: Optional[int] = None
) -> Import:
    return Import(ea=Address(addr), name=name, module=module, ordinal=ordinal)


def _use_case(
    funcs: Optional[List[Function]] = None,
    globs: Optional[List[Global]] = None,
    imps: Optional[List[Import]] = None,
) -> EntityQueryUseCase:
    return EntityQueryUseCase(
        _FakeFunctionRepository(list(funcs or [])),
        _FakeGlobalRepository(list(globs or [])),
        _FakeImportRepository(list(imps or [])),
    )


def _names(result: EntityQueryResult) -> List[str]:
    return [m.name for m in result.matches]


def _kinds(result: EntityQueryResult) -> List[str]:
    return [m.kind for m in result.matches]


# -- kind selection -------------------------------------------------------


def test_any_spans_all_three_repositories_in_order():
    use_case = _use_case(
        funcs=[_func(0x1000, "main"), _func(0x1010, "helper")],
        globs=[_glob(0x4000, "g_table")],
        imps=[_imp(0x8000, "malloc", "ucrtbase.dll", 1)],
    )

    result = use_case.execute(EntityQueryCommand(query="", kind="any"))

    # Functions first, then globals, then imports — the chained source order.
    assert _names(result) == ["main", "helper", "g_table", "malloc"]
    assert _kinds(result) == [
        KIND_FUNCTION,
        KIND_FUNCTION,
        KIND_GLOBAL,
        KIND_IMPORT,
    ]
    assert result.truncated is False


def test_kind_function_draws_only_functions():
    use_case = _use_case(
        funcs=[_func(0x1000, "encrypt")],
        globs=[_glob(0x4000, "encrypt_key")],
        imps=[_imp(0x8000, "encrypt_api", "crypt.dll")],
    )

    result = use_case.execute(EntityQueryCommand(kind="function"))

    assert _names(result) == ["encrypt"]
    assert _kinds(result) == [KIND_FUNCTION]


def test_kind_global_draws_only_globals():
    use_case = _use_case(
        funcs=[_func(0x1000, "encrypt")],
        globs=[_glob(0x4000, "encrypt_key")],
        imps=[_imp(0x8000, "encrypt_api", "crypt.dll")],
    )

    result = use_case.execute(EntityQueryCommand(kind="global"))

    assert _names(result) == ["encrypt_key"]
    assert _kinds(result) == [KIND_GLOBAL]


def test_kind_import_draws_only_imports():
    use_case = _use_case(
        funcs=[_func(0x1000, "encrypt")],
        globs=[_glob(0x4000, "encrypt_key")],
        imps=[_imp(0x8000, "encrypt_api", "crypt.dll")],
    )

    result = use_case.execute(EntityQueryCommand(kind="import"))

    assert _names(result) == ["encrypt_api"]
    assert _kinds(result) == [KIND_IMPORT]


def test_kind_filter_does_not_touch_unselected_repositories():
    funcs = _FakeFunctionRepository([_func(0x1000, "main")])
    globs = _FakeGlobalRepository([_glob(0x4000, "g")])
    imps = _FakeImportRepository([_imp(0x8000, "malloc", "libc")])
    use_case = EntityQueryUseCase(funcs, globs, imps)

    use_case.execute(EntityQueryCommand(kind="function"))

    # Only the function repository was ever enumerated.
    assert funcs.requests
    assert globs.requests == []
    assert imps.requests == []


# -- kind normalization and validation ------------------------------------


def test_kind_is_normalized_case_and_whitespace_insensitively():
    use_case = _use_case(funcs=[_func(0x1000, "main")])

    result = use_case.execute(EntityQueryCommand(kind="  FUNCTION  "))

    assert result.kind == "function"
    assert _names(result) == ["main"]


def test_empty_kind_defaults_to_any():
    use_case = _use_case(
        funcs=[_func(0x1000, "f")],
        globs=[_glob(0x4000, "g")],
        imps=[_imp(0x8000, "i", "m")],
    )

    result = use_case.execute(EntityQueryCommand(kind="   "))

    assert result.kind == "any"
    assert _names(result) == ["f", "g", "i"]


def test_unknown_kind_raises_value_error():
    use_case = _use_case(funcs=[_func(0x1000, "main")])

    with pytest.raises(ValueError):
        use_case.execute(EntityQueryCommand(kind="method"))


def test_entity_kinds_vocabulary_is_frozen():
    assert ENTITY_KINDS == ("any", "function", "global", "import")


# -- name filtering -------------------------------------------------------


def test_empty_query_matches_every_name():
    use_case = _use_case(funcs=[_func(0x1000, "a"), _func(0x1010, "b")])

    result = use_case.execute(EntityQueryCommand(query="", kind="function"))

    assert _names(result) == ["a", "b"]


def test_name_substring_is_case_insensitive():
    use_case = _use_case(
        funcs=[
            _func(0x1000, "DecryptBuffer"),
            _func(0x1010, "main"),
            _func(0x1020, "sub_ENCRYPT"),
        ]
    )

    result = use_case.execute(EntityQueryCommand(query="crypt", kind="function"))

    assert _names(result) == ["DecryptBuffer", "sub_ENCRYPT"]


def test_name_filter_spans_kinds_under_any():
    use_case = _use_case(
        funcs=[_func(0x1000, "aes_encrypt"), _func(0x1010, "main")],
        globs=[_glob(0x4000, "aes_sbox"), _glob(0x4010, "counter")],
        imps=[_imp(0x8000, "AesEncrypt", "bcrypt.dll"), _imp(0x8010, "free", "libc")],
    )

    result = use_case.execute(EntityQueryCommand(query="aes", kind="any"))

    assert _names(result) == ["aes_encrypt", "aes_sbox", "AesEncrypt"]
    assert _kinds(result) == [KIND_FUNCTION, KIND_GLOBAL, KIND_IMPORT]


def test_whitespace_only_query_matches_everything():
    use_case = _use_case(funcs=[_func(0x1000, "a"), _func(0x1010, "b")])

    result = use_case.execute(EntityQueryCommand(query="   ", kind="function"))

    assert _names(result) == ["a", "b"]


def test_no_matches_yields_empty_untruncated():
    use_case = _use_case(funcs=[_func(0x1000, "alpha"), _func(0x1010, "beta")])

    result = use_case.execute(EntityQueryCommand(query="zzz", kind="function"))

    assert result.matches == ()
    assert result.truncated is False


def test_result_echoes_query_verbatim_preserving_case():
    use_case = _use_case(funcs=[_func(0x1000, "Init")])

    result = use_case.execute(EntityQueryCommand(query="INIT", kind="function"))

    assert result.query == "INIT"
    assert _names(result) == ["Init"]


# -- limit, clamping, and truncation --------------------------------------


def test_limit_caps_matches_and_flags_truncated():
    use_case = _use_case(
        funcs=[_func(0x1000 + i * 0x10, f"fn{i}") for i in range(5)]
    )

    result = use_case.execute(EntityQueryCommand(kind="function", limit=2))

    assert _names(result) == ["fn0", "fn1"]
    assert result.truncated is True


def test_exact_limit_is_not_truncated():
    use_case = _use_case(
        funcs=[_func(0x1000 + i * 0x10, f"fn{i}") for i in range(3)]
    )

    result = use_case.execute(EntityQueryCommand(kind="function", limit=3))

    assert len(result.matches) == 3
    assert result.truncated is False


def test_truncation_detected_across_the_unified_stream():
    # The limit is reached inside the function source; the one-beyond match
    # lives in the global source, so truncation is a whole-stream property.
    use_case = _use_case(
        funcs=[_func(0x1000, "f0"), _func(0x1010, "f1")],
        globs=[_glob(0x4000, "g0")],
    )

    result = use_case.execute(EntityQueryCommand(kind="any", limit=2))

    assert _names(result) == ["f0", "f1"]
    assert result.truncated is True


def test_limit_zero_with_matches_present_is_truncated():
    use_case = _use_case(funcs=[_func(0x1000, "main")])

    result = use_case.execute(EntityQueryCommand(kind="function", limit=0))

    assert result.matches == ()
    assert result.truncated is True


def test_limit_zero_with_no_matches_is_untruncated():
    use_case = _use_case(funcs=[_func(0x1000, "main")])

    result = use_case.execute(
        EntityQueryCommand(query="nomatch", kind="function", limit=0)
    )

    assert result.matches == ()
    assert result.truncated is False


def test_negative_limit_degenerates_to_zero_but_signals_truncation():
    use_case = _use_case(funcs=[_func(0x1000, "a"), _func(0x1010, "b")])

    result = use_case.execute(EntityQueryCommand(kind="function", limit=-5))

    assert result.matches == ()
    assert result.truncated is True


def test_limit_clamped_to_server_maximum():
    # More matches than the hard ceiling, spread across the paging boundary.
    total = MAX_ENTITY_QUERY_LIMIT + 5
    funcs = [_func(0x140001000 + i * 0x10, f"fn_{i}") for i in range(total)]
    use_case = _use_case(funcs=funcs)

    result = use_case.execute(
        EntityQueryCommand(query="fn_", kind="function", limit=10_000_000)
    )

    assert len(result.matches) == MAX_ENTITY_QUERY_LIMIT
    assert result.truncated is True


# -- cross-page enumeration -----------------------------------------------


def test_enumerates_matches_beyond_the_first_page():
    # One matching function lives strictly beyond the first repository page, so
    # it is only found if the walk crosses the page boundary.
    filler = [_func(0x140001000 + i * 0x10, f"filler_{i}") for i in range(MAX_COUNT)]
    needle = _func(0x140001000 + MAX_COUNT * 0x10, "needle_fn")
    repo = _FakeFunctionRepository(filler + [needle])
    use_case = EntityQueryUseCase(
        repo, _FakeGlobalRepository([]), _FakeImportRepository([])
    )

    result = use_case.execute(EntityQueryCommand(query="needle", kind="function"))

    assert _names(result) == ["needle_fn"]
    assert result.truncated is False
    assert len(repo.requests) >= 2
    assert repo.requests[1].offset == MAX_COUNT


# -- projection to NamedEntity --------------------------------------------


def test_function_projection_carries_size_only():
    use_case = _use_case(funcs=[_func(0x401000, "target", size=0x40)])

    (entity,) = use_case.execute(EntityQueryCommand(kind="function")).matches

    assert isinstance(entity, NamedEntity)
    assert entity.name == "target"
    assert entity.ea == Address(0x401000)
    assert entity.kind == KIND_FUNCTION
    assert entity.size == 0x40
    assert entity.module is None
    assert entity.ordinal is None


def test_global_projection_carries_size_only():
    use_case = _use_case(globs=[_glob(0x4000, "g_state", size=0x100)])

    (entity,) = use_case.execute(EntityQueryCommand(kind="global")).matches

    assert entity.kind == KIND_GLOBAL
    assert entity.size == 0x100
    assert entity.module is None
    assert entity.ordinal is None


def test_import_projection_carries_module_and_ordinal_not_size():
    use_case = _use_case(
        imps=[_imp(0x8000, "CreateFileW", "kernel32.dll", ordinal=42)]
    )

    (entity,) = use_case.execute(EntityQueryCommand(kind="import")).matches

    assert entity.kind == KIND_IMPORT
    assert entity.module == "kernel32.dll"
    assert entity.ordinal == 42
    assert entity.size is None


# -- wire view ------------------------------------------------------------


def test_match_view_of_function_nulls_import_extras():
    view = entity_match_view(
        NamedEntity(name="sub_x", ea=Address(0x140001000), kind=KIND_FUNCTION, size=16)
    )

    assert view == {
        "name": "sub_x",
        "address": "0x140001000",
        "kind": "function",
        "size": 16,
        "module": None,
        "ordinal": None,
    }


def test_match_view_of_import_nulls_size():
    view = entity_match_view(
        NamedEntity(
            name="malloc",
            ea=Address(0x8000),
            kind=KIND_IMPORT,
            module="ucrtbase.dll",
            ordinal=7,
        )
    )

    assert view == {
        "name": "malloc",
        "address": "0x8000",
        "kind": "import",
        "size": None,
        "module": "ucrtbase.dll",
        "ordinal": 7,
    }


def test_query_view_projects_full_result_shape():
    result = EntityQueryResult(
        query="enc",
        kind="any",
        matches=(
            NamedEntity(name="encrypt", ea=Address(0x401000), kind=KIND_FUNCTION, size=32),
            NamedEntity(
                name="EncryptApi",
                ea=Address(0x8000),
                kind=KIND_IMPORT,
                module="crypt.dll",
                ordinal=3,
            ),
        ),
        truncated=True,
    )

    view = entity_query_view(result)

    assert view["query"] == "enc"
    assert view["kind"] == "any"
    assert view["truncated"] is True
    assert view["matches"] == [
        {
            "name": "encrypt",
            "address": "0x401000",
            "kind": "function",
            "size": 32,
            "module": None,
            "ordinal": None,
        },
        {
            "name": "EncryptApi",
            "address": "0x8000",
            "kind": "import",
            "size": None,
            "module": "crypt.dll",
            "ordinal": 3,
        },
    ]


def test_end_to_end_use_case_to_view():
    use_case = _use_case(
        funcs=[_func(0x1000, "aes_key_expand", size=0x80)],
        globs=[_glob(0x4000, "aes_rcon", size=0x28)],
        imps=[_imp(0x8000, "AesEncrypt", "bcrypt.dll", ordinal=9)],
    )

    result = use_case.execute(EntityQueryCommand(query="aes", kind="any", limit=100))
    view = entity_query_view(result)

    assert [m["name"] for m in view["matches"]] == [
        "aes_key_expand",
        "aes_rcon",
        "AesEncrypt",
    ]
    assert [m["kind"] for m in view["matches"]] == ["function", "global", "import"]
    assert view["matches"][0]["size"] == 0x80
    assert view["matches"][2]["module"] == "bcrypt.dll"
    assert view["matches"][2]["ordinal"] == 9
    assert view["truncated"] is False


# -- shared pure predicate grammar (authored for these tools) -------------


def test_empty_query_matches_any_features():
    assert Query().is_empty is True
    assert Query().matches({"name": "anything"}) is True


def test_query_of_drops_none_predicates():
    query = Query.of(None, FieldPredicate("name", FieldOp.EQ, "main"), None)

    assert len(query.predicates) == 1
    assert query.matches({"name": "main"}) is True


def test_missing_field_is_false_not_raised():
    predicate = FieldPredicate("size", FieldOp.GE, 10)

    assert predicate.evaluate({"name": "x"}) is False


def test_contains_is_case_insensitive_substring():
    predicate = FieldPredicate("name", FieldOp.CONTAINS, "CRYPT")

    assert predicate.evaluate({"name": "sub_decrypt"}) is True
    assert predicate.evaluate({"name": "main"}) is False


def test_string_equality_is_case_folded():
    predicate = FieldPredicate("module", FieldOp.EQ, "Kernel32.DLL")

    assert predicate.evaluate({"module": "kernel32.dll"}) is True


def test_bool_is_never_a_magnitude():
    # A boolean field must not satisfy a numeric comparison.
    assert FieldPredicate("flag", FieldOp.GE, 0).evaluate({"flag": True}) is False
    # But the truthiness operators reach it.
    assert FieldPredicate("flag", FieldOp.IS_TRUE, None).evaluate({"flag": True}) is True
    assert (
        FieldPredicate("flag", FieldOp.IS_FALSE, None).evaluate({"flag": False}) is True
    )


def test_magnitude_operators_compare_integers():
    features = {"size": 16}

    assert FieldPredicate("size", FieldOp.GE, 16).evaluate(features) is True
    assert FieldPredicate("size", FieldOp.GT, 16).evaluate(features) is False
    assert FieldPredicate("size", FieldOp.LE, 16).evaluate(features) is True
    assert FieldPredicate("size", FieldOp.LT, 16).evaluate(features) is False


def test_has_tests_membership_but_not_string_containment():
    assert FieldPredicate("regs", FieldOp.HAS, "rax").evaluate(
        {"regs": ("rax", "rbx")}
    ) is True
    assert FieldPredicate("regs", FieldOp.HAS, "rcx").evaluate(
        {"regs": ("rax", "rbx")}
    ) is False
    # A string is not treated as a collection of characters.
    assert FieldPredicate("name", FieldOp.HAS, "a").evaluate({"name": "rax"}) is False


def test_conjunction_requires_all_predicates():
    query = Query.of(
        FieldPredicate("name", FieldOp.CONTAINS, "enc"),
        FieldPredicate("size", FieldOp.GE, 32),
    )

    assert query.matches({"name": "encrypt", "size": 64}) is True
    assert query.matches({"name": "encrypt", "size": 8}) is False
    assert query.matches({"name": "main", "size": 64}) is False
