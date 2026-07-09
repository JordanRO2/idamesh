"""Unit tests for the ``xrefs_to`` and ``callees`` use-cases and views (no IDA).

A fake :class:`XrefRepository` and a fake database gateway stand in for the IDA
adapter, so the selector-resolution, per-call capping, and wire-projection
contracts of both tools are exercised without a database. The fake gateway
resolves through the real :class:`Selector`, covering hex, decimal, and symbol
inputs plus the unresolved-symbol failure path.
"""

from __future__ import annotations

import pytest

from idamesh.application.contexts.xrefs import CalleesUseCase, XrefsToUseCase
from idamesh.application.dto.xrefs import (
    CALLEES_LIMIT,
    XREFS_TO_LIMIT,
    CalleesCommand,
    XrefsToCommand,
)
from idamesh.domain.entities.xref import Xref, XrefKind, XrefType
from idamesh.domain.values.address import Address, Selector
from idamesh.interface.catalog.callees import callee_view, callees_view
from idamesh.interface.catalog.xrefs import xref_view, xrefs_to_view


class _FakeDatabase:
    """A resolver-backed database gateway over a fixed symbol table."""

    def __init__(self, symbols: dict[str, int] | None = None) -> None:
        self._symbols = symbols or {}

    def resolve_symbol(self, name: str) -> int | None:
        return self._symbols.get(name)

    def resolve(self, selector: Selector) -> Address:
        # Mirror the real gateway: numeric kinds parse directly, symbols look up.
        return selector.resolve(self)


class _FakeXrefRepository:
    """An in-memory ``XrefRepository`` over fixed inbound/outbound edge maps."""

    def __init__(
        self,
        refs: dict[int, list[Xref]] | None = None,
        calls: dict[int, list[Xref]] | None = None,
        no_function: set[int] | None = None,
    ) -> None:
        self._refs = refs or {}
        self._calls = calls or {}
        self._no_function = no_function or set()
        self.refs_to_seen: list[Address] = []
        self.callees_seen: list[Address] = []

    def refs_to(self, ea: Address) -> list[Xref]:
        self.refs_to_seen.append(ea)
        return list(self._refs.get(int(ea), []))

    def callees(self, ea: Address) -> list[Xref]:
        self.callees_seen.append(ea)
        if int(ea) in self._no_function:
            raise LookupError(f"no function contains {ea.hex()}")
        return list(self._calls.get(int(ea), []))


def _code_ref(src: int, dst: int, func: str | None) -> Xref:
    return Xref(
        source=Address(src),
        target=Address(dst),
        kind=XrefKind.CODE,
        ref_type=XrefType.CALL,
        source_func=func,
    )


def _call_edge(src: int, dst: int, name: str | None) -> Xref:
    return Xref(
        source=Address(src),
        target=Address(dst),
        kind=XrefKind.CODE,
        ref_type=XrefType.CALL,
        target_name=name,
    )


# -- xrefs_to use-case ------------------------------------------------------


def test_xrefs_to_resolves_hex_and_returns_edges():
    target = 0x401000
    repo = _FakeXrefRepository(
        refs={
            target: [
                _code_ref(0x401500, target, "caller_a"),
                _code_ref(0x402200, target, "caller_b"),
            ]
        }
    )
    use_case = XrefsToUseCase(repo, _FakeDatabase())

    result = use_case.execute(XrefsToCommand(address="0x401000"))

    assert result.target == Address(target)
    assert repo.refs_to_seen == [Address(target)]
    assert [edge.source_func for edge in result.xrefs] == ["caller_a", "caller_b"]
    assert result.truncated is False


def test_xrefs_to_resolves_decimal_and_symbol():
    sym_ea = 0x404040
    repo = _FakeXrefRepository(refs={4198400: [], sym_ea: []})
    database = _FakeDatabase(symbols={"handler": sym_ea})
    use_case = XrefsToUseCase(repo, database)

    dec = use_case.execute(XrefsToCommand(address="4198400"))
    assert dec.target == Address(4198400)

    sym = use_case.execute(XrefsToCommand(address="handler"))
    assert sym.target == Address(sym_ea)


def test_xrefs_to_unresolvable_symbol_raises():
    use_case = XrefsToUseCase(_FakeXrefRepository(), _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(XrefsToCommand(address="nope"))


def test_xrefs_to_caps_edges_and_flags_truncation():
    target = 0x410000
    edges = [_code_ref(0x420000 + i * 4, target, None) for i in range(XREFS_TO_LIMIT + 25)]
    repo = _FakeXrefRepository(refs={target: edges})
    use_case = XrefsToUseCase(repo, _FakeDatabase())

    result = use_case.execute(XrefsToCommand(address=hex(target)))

    assert len(result.xrefs) == XREFS_TO_LIMIT
    assert result.truncated is True


def test_xrefs_to_at_limit_is_not_truncated():
    target = 0x411000
    edges = [_code_ref(0x430000 + i * 4, target, None) for i in range(XREFS_TO_LIMIT)]
    repo = _FakeXrefRepository(refs={target: edges})
    use_case = XrefsToUseCase(repo, _FakeDatabase())

    result = use_case.execute(XrefsToCommand(address=hex(target)))

    assert len(result.xrefs) == XREFS_TO_LIMIT
    assert result.truncated is False


# -- xrefs_to view ----------------------------------------------------------


def test_xref_view_projects_code_call_edge():
    view = xref_view(_code_ref(0x401500, 0x401000, "main"))

    assert view == {
        "from": "0x401500",
        "to": "0x401000",
        "kind": "code",
        "type": "call",
        "func": "main",
    }


def test_xref_view_projects_data_write_without_owner():
    edge = Xref(
        source=Address(0x403000),
        target=Address(0x601020),
        kind=XrefKind.DATA,
        ref_type=XrefType.WRITE,
        source_func=None,
    )

    view = xref_view(edge)

    assert view["kind"] == "data"
    assert view["type"] == "write"
    assert view["func"] is None


def test_xrefs_to_view_projects_result():
    from idamesh.application.dto.xrefs import XrefsToResult

    result = XrefsToResult(
        target=Address(0x401000),
        xrefs=(
            _code_ref(0x401500, 0x401000, "a"),
            _code_ref(0x402000, 0x401000, None),
        ),
        truncated=True,
    )

    view = xrefs_to_view(result)

    assert view["target"] == "0x401000"
    assert len(view["xrefs"]) == 2
    assert view["xrefs"][0]["from"] == "0x401500"
    assert view["xrefs"][1]["func"] is None
    assert view["truncated"] is True


# -- callees use-case -------------------------------------------------------


def test_callees_resolves_and_echoes_function():
    func = 0x401000
    repo = _FakeXrefRepository(
        calls={
            func: [
                _call_edge(0x401010, 0x402000, "helper"),
                _call_edge(0x401030, 0x403000, "printf"),
            ]
        }
    )
    use_case = CalleesUseCase(repo, _FakeDatabase())

    result = use_case.execute(CalleesCommand(address="0x401000"))

    assert result.func == Address(func)
    assert repo.callees_seen == [Address(func)]
    assert [edge.target.value for edge in result.callees] == [0x402000, 0x403000]
    assert result.truncated is False


def test_callees_resolves_symbol_anchor():
    func = 0x408000
    repo = _FakeXrefRepository(calls={func: [_call_edge(0x408010, 0x409000, "sub")]})
    database = _FakeDatabase(symbols={"start": func})
    use_case = CalleesUseCase(repo, database)

    result = use_case.execute(CalleesCommand(address="start"))

    assert result.func == Address(func)
    assert result.callees[0].target == Address(0x409000)


def test_callees_caps_and_flags_truncation():
    func = 0x412000
    edges = [
        _call_edge(0x412000 + i * 8, 0x450000 + i * 8, None)
        for i in range(CALLEES_LIMIT + 10)
    ]
    repo = _FakeXrefRepository(calls={func: edges})
    use_case = CalleesUseCase(repo, _FakeDatabase())

    result = use_case.execute(CalleesCommand(address=hex(func)))

    assert len(result.callees) == CALLEES_LIMIT
    assert result.truncated is True


def test_callees_out_of_function_propagates_error():
    orphan = 0x600100
    repo = _FakeXrefRepository(no_function={orphan})
    use_case = CalleesUseCase(repo, _FakeDatabase())

    with pytest.raises(LookupError):
        use_case.execute(CalleesCommand(address=hex(orphan)))


# -- callees view -----------------------------------------------------------


def test_callee_view_projects_named_and_anonymous():
    named = callee_view(_call_edge(0x401010, 0x402000, "helper"))
    anon = callee_view(_call_edge(0x401020, 0x403000, None))

    assert named == {"addr": "0x402000", "name": "helper"}
    assert anon == {"addr": "0x403000", "name": None}


def test_callees_view_projects_result():
    from idamesh.application.dto.xrefs import CalleesResult

    result = CalleesResult(
        func=Address(0x401000),
        callees=(
            _call_edge(0x401010, 0x402000, "helper"),
            _call_edge(0x401030, 0x403000, "printf"),
        ),
        truncated=False,
    )

    view = callees_view(result)

    assert view["func"] == "0x401000"
    assert [c["addr"] for c in view["callees"]] == ["0x402000", "0x403000"]
    assert view["callees"][1]["name"] == "printf"
    assert view["truncated"] is False
