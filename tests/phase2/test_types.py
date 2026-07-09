"""Unit tests for the type tools (no IDA).

A fake :class:`~idamesh.domain.ports.types.TypeGateway` stands in for the IDA
adapter so the two use-cases' contracts are exercised without a database:
``type_query``'s case-insensitive substring filter, limit clamping, and the
``truncated`` flag (driven by the gateway being asked for one match beyond the
cap), and ``type_inspect``'s member projection and unknown-name-is-an-error rule.
The wire views are covered over hand-built entities, keeping the module IDA-free.
"""

from __future__ import annotations

from typing import List, Optional

import pytest

from idamesh.application.contexts.types import (
    TypeInspectUseCase,
    TypeQueryUseCase,
)
from idamesh.application.dto.types import (
    MAX_TYPE_QUERY_LIMIT,
    TypeInspectCommand,
    TypeInspectResult,
    TypeQueryCommand,
)
from idamesh.domain.entities.type_info import TypeInfo, TypeMember
from idamesh.interface.catalog.type_inspect import (
    type_inspect_view,
    type_member_view,
)
from idamesh.interface.catalog.type_query import (
    type_match_view,
    type_query_view,
)


class _FakeTypeGateway:
    """An in-memory ``TypeGateway`` over a fixed catalog of named types.

    :meth:`list_types` owns the case-insensitive substring filter and honours the
    caller's ``limit`` exactly (returning at most that many hits), so a use-case
    that asks for ``limit + 1`` can observe an elided remainder. Every gateway
    call is recorded so a test can assert the exact ``limit`` the use-case passed.
    """

    def __init__(self, types: List[TypeInfo]) -> None:
        self._types = types
        self.list_calls: List[tuple[str, int]] = []
        self.get_calls: List[str] = []

    def list_types(self, query: str, limit: int) -> List[TypeInfo]:
        self.list_calls.append((query, limit))
        needle = query.casefold()
        hits = [t for t in self._types if needle in t.name.casefold()]
        if limit < 0:
            limit = 0
        return hits[:limit]

    def get_type(self, name: str) -> Optional[TypeInfo]:
        self.get_calls.append(name)
        for t in self._types:
            if t.name == name:
                return t
        return None


def _scalar(name: str, size: int = 4) -> TypeInfo:
    return TypeInfo(name=name, kind="scalar", size=size)


def _catalog(names: List[str]) -> List[TypeInfo]:
    return [_scalar(name) for name in names]


# -- type_query: substring matching ---------------------------------------


def test_query_matches_by_name_substring():
    gateway = _FakeTypeGateway(
        _catalog(["FILE", "sockaddr", "tagRECT", "sockaddr_in"])
    )
    use_case = TypeQueryUseCase(gateway)

    result = use_case.execute(TypeQueryCommand(query="sockaddr"))

    assert [t.name for t in result.matches] == ["sockaddr", "sockaddr_in"]
    assert result.truncated is False


def test_query_is_case_insensitive():
    gateway = _FakeTypeGateway(_catalog(["FileHeader", "RECT", "filetime"]))
    use_case = TypeQueryUseCase(gateway)

    result = use_case.execute(TypeQueryCommand(query="file"))

    assert [t.name for t in result.matches] == ["FileHeader", "filetime"]


def test_empty_query_matches_every_type():
    gateway = _FakeTypeGateway(_catalog(["a", "b", "c"]))
    use_case = TypeQueryUseCase(gateway)

    result = use_case.execute(TypeQueryCommand(query=""))

    assert [t.name for t in result.matches] == ["a", "b", "c"]
    assert result.truncated is False


def test_query_no_matches_is_empty_and_untruncated():
    gateway = _FakeTypeGateway(_catalog(["alpha", "beta"]))
    use_case = TypeQueryUseCase(gateway)

    result = use_case.execute(TypeQueryCommand(query="zzz"))

    assert result.matches == ()
    assert result.truncated is False


def test_query_on_empty_catalog_is_valid_not_error():
    use_case = TypeQueryUseCase(_FakeTypeGateway([]))

    result = use_case.execute(TypeQueryCommand(query="anything"))

    assert result.matches == ()
    assert result.truncated is False


def test_query_echoes_original_query_verbatim():
    gateway = _FakeTypeGateway(_catalog(["Widget"]))
    use_case = TypeQueryUseCase(gateway)

    result = use_case.execute(TypeQueryCommand(query="WID"))

    # The echoed query preserves the caller's original casing.
    assert result.query == "WID"


# -- type_query: limit, truncation, one-beyond probe ----------------------


def test_query_limit_caps_matches_and_flags_truncated():
    gateway = _FakeTypeGateway(_catalog(["t0", "t1", "t2", "t3", "t4"]))
    use_case = TypeQueryUseCase(gateway)

    result = use_case.execute(TypeQueryCommand(query="t", limit=2))

    assert [t.name for t in result.matches] == ["t0", "t1"]
    assert result.truncated is True


def test_query_exact_limit_is_not_truncated():
    gateway = _FakeTypeGateway(_catalog(["t0", "t1", "t2"]))
    use_case = TypeQueryUseCase(gateway)

    result = use_case.execute(TypeQueryCommand(query="t", limit=3))

    assert len(result.matches) == 3
    assert result.truncated is False


def test_query_asks_gateway_for_one_beyond_the_cap():
    gateway = _FakeTypeGateway(_catalog(["t0", "t1", "t2"]))
    use_case = TypeQueryUseCase(gateway)

    use_case.execute(TypeQueryCommand(query="t", limit=2))

    # The probe for the truncation flag requests limit + 1 in one round-trip.
    assert gateway.list_calls[-1] == ("t", 3)


def test_query_negative_limit_returns_no_matches_but_flags_truncated():
    gateway = _FakeTypeGateway(_catalog(["t0", "t1"]))
    use_case = TypeQueryUseCase(gateway)

    result = use_case.execute(TypeQueryCommand(query="t", limit=-1))

    # A negative limit degenerates to zero; the existence of matches is still
    # signalled through ``truncated``.
    assert result.matches == ()
    assert result.truncated is True


def test_query_limit_clamped_to_server_maximum():
    names = [f"t_{i}" for i in range(MAX_TYPE_QUERY_LIMIT + 5)]
    gateway = _FakeTypeGateway(_catalog(names))
    use_case = TypeQueryUseCase(gateway)

    result = use_case.execute(TypeQueryCommand(query="t_", limit=10_000_000))

    assert len(result.matches) == MAX_TYPE_QUERY_LIMIT
    assert result.truncated is True
    # The oversized request is clamped before it reaches the gateway.
    assert gateway.list_calls[-1] == ("t_", MAX_TYPE_QUERY_LIMIT + 1)


# -- type_inspect ---------------------------------------------------------


def test_inspect_returns_full_type_with_members():
    point = TypeInfo(
        name="Point",
        kind="struct",
        size=8,
        members=(
            TypeMember(name="x", type_name="int", offset=0, size=4),
            TypeMember(name="y", type_name="int", offset=4, size=4),
        ),
    )
    use_case = TypeInspectUseCase(_FakeTypeGateway([point]))

    result = use_case.execute(TypeInspectCommand(name="Point"))

    assert isinstance(result, TypeInspectResult)
    info = result.type_info
    assert info.name == "Point"
    assert info.kind == "struct"
    assert info.size == 8
    assert [(m.name, m.offset, m.size) for m in info.members] == [
        ("x", 0, 4),
        ("y", 4, 4),
    ]


def test_inspect_non_aggregate_has_empty_members():
    use_case = TypeInspectUseCase(_FakeTypeGateway([_scalar("DWORD", size=4)]))

    result = use_case.execute(TypeInspectCommand(name="DWORD"))

    assert result.type_info.members == ()


def test_inspect_unknown_type_raises():
    use_case = TypeInspectUseCase(_FakeTypeGateway(_catalog(["Known"])))

    with pytest.raises(ValueError):
        use_case.execute(TypeInspectCommand(name="Missing"))


# -- view projection ------------------------------------------------------


def test_type_match_view_projects_single_type():
    view = type_match_view(TypeInfo(name="sockaddr", kind="struct", size=16))

    assert view == {"name": "sockaddr", "kind": "struct", "size": 16}


def test_type_query_view_projects_result_to_wire_shape():
    gateway = _FakeTypeGateway(
        [
            TypeInfo(name="FILE", kind="struct", size=48),
            TypeInfo(name="FILETIME", kind="struct", size=8),
        ]
    )
    result = TypeQueryUseCase(gateway).execute(TypeQueryCommand(query="file"))

    view = type_query_view(result)

    assert view["query"] == "file"
    assert view["truncated"] is False
    assert view["matches"] == [
        {"name": "FILE", "kind": "struct", "size": 48},
        {"name": "FILETIME", "kind": "struct", "size": 8},
    ]


def test_type_member_view_projects_domain_type_name_to_wire_key():
    view = type_member_view(
        TypeMember(name="cb", type_name="unsigned int", offset=0, size=4)
    )

    # The domain ``type_name`` is projected to the wire key ``type``.
    assert view == {"name": "cb", "type": "unsigned int", "offset": 0, "size": 4}


def test_type_inspect_view_expands_members():
    info = TypeInfo(
        name="RECT",
        kind="struct",
        size=16,
        members=(
            TypeMember(name="left", type_name="int", offset=0, size=4),
            TypeMember(name="top", type_name="int", offset=4, size=4),
        ),
    )

    view = type_inspect_view(info)

    assert view["name"] == "RECT"
    assert view["kind"] == "struct"
    assert view["size"] == 16
    assert view["members"] == [
        {"name": "left", "type": "int", "offset": 0, "size": 4},
        {"name": "top", "type": "int", "offset": 4, "size": 4},
    ]


def test_type_inspect_view_empty_members_is_empty_list():
    view = type_inspect_view(TypeInfo(name="DWORD", kind="scalar", size=4))

    assert view["members"] == []
