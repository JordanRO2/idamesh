"""Unit tests for the ``rename`` mutation tool (no IDA).

Fake :class:`NamingGateway` and :class:`DatabaseGateway` implementations stand in
for the IDA adapters, so the whole write path is exercised off-host: the use-case
resolves a polymorphic selector, validates the requested name, captures the prior
name, and installs the new one; the ``RenameView`` projects the completed change;
and the registered tool marshals through the executor, advertises ``readOnlyHint:
false``, and turns a rejected name into an ``isError`` (``ToolError``) instead of a
crash.
"""

from __future__ import annotations

import pytest

from idamesh.application.contexts.rename import RenameUseCase
from idamesh.application.dto.rename import RenameCommand
from idamesh.domain.entities.rename import Renaming
from idamesh.domain.values.address import Address, Selector
from idamesh.infrastructure.execution.inline import InlineExecutor
from idamesh.interface.catalog.rename import register_rename, rename_view
from idamesh.interface.mcp.engine import ToolError
from idamesh.interface.mcp.registry import Registry


class _FakeDatabaseGateway:
    """Resolves selectors: numeric kinds parse directly, symbols via a table."""

    def __init__(self, symbols: dict[str, int] | None = None) -> None:
        self._symbols = dict(symbols or {})

    def resolve_symbol(self, name: str) -> int | None:
        return self._symbols.get(name)

    def resolve(self, selector: Selector) -> Address:
        # Delegate to the selector's own resolution, using this gateway as the
        # structural ``SymbolResolver`` — exactly as the real database adapter does.
        return selector.resolve(self)


class _FakeNamingGateway:
    """In-memory naming gateway: records writes, models prior names and clashes.

    ``prior`` maps an EA to the name shown there before any write; ``reserved`` is
    the set of names already bound elsewhere, so writing one raises — mirroring the
    adapter's ``SN_CHECK`` refusal of a colliding name rather than uniquifying it.
    """

    def __init__(
        self,
        prior: dict[int, str] | None = None,
        reserved: set[str] | None = None,
    ) -> None:
        self._prior = dict(prior or {})
        self._reserved = set(reserved or set())
        self.calls: list[tuple[int, str]] = []

    def set_name(self, ea: Address, name: str) -> str:
        if name in self._reserved:
            raise ValueError(
                f"cannot rename {ea.hex()} to {name!r}: name already in use"
            )
        self.calls.append((int(ea), name))
        old = self._prior.get(int(ea), "")
        self._prior[int(ea)] = name
        return old


# --------------------------------------------------------------------------- #
# Use-case: happy path
# --------------------------------------------------------------------------- #


def test_use_case_sets_name_and_reports_prior_name():
    naming = _FakeNamingGateway(prior={0x401000: "sub_401000"})
    database = _FakeDatabaseGateway()
    use_case = RenameUseCase(naming, database)

    result = use_case.execute(RenameCommand(address="0x401000", name="parse_header"))

    renaming = result.renaming
    assert isinstance(renaming, Renaming)
    assert renaming.address == Address(0x401000)
    assert renaming.old_name == "sub_401000"
    assert renaming.name == "parse_header"
    # The gateway saw exactly one write, at the resolved EA, with the new name.
    assert naming.calls == [(0x401000, "parse_header")]


def test_use_case_reports_empty_prior_name_for_unnamed_item():
    naming = _FakeNamingGateway()
    use_case = RenameUseCase(naming, _FakeDatabaseGateway())

    result = use_case.execute(RenameCommand(address="0x401000", name="handler"))

    # An item that carried no user name reports an empty ``old_name``.
    assert result.renaming.old_name == ""
    assert result.renaming.name == "handler"


def test_use_case_resolves_symbol_selector_before_writing():
    naming = _FakeNamingGateway(prior={0x401000: "sub_401000"})
    database = _FakeDatabaseGateway(symbols={"sub_401000": 0x401000})
    use_case = RenameUseCase(naming, database)

    result = use_case.execute(RenameCommand(address="sub_401000", name="decode"))

    # The symbol name was resolved to its EA, and the write targeted that EA.
    assert naming.calls == [(0x401000, "decode")]
    assert result.renaming.address == Address(0x401000)
    assert result.renaming.name == "decode"


def test_use_case_resolves_decimal_selector():
    naming = _FakeNamingGateway()
    use_case = RenameUseCase(naming, _FakeDatabaseGateway())

    use_case.execute(RenameCommand(address="4198400", name="entry"))  # 0x401000

    assert naming.calls == [(0x401000, "entry")]


def test_use_case_strips_surrounding_whitespace_from_name():
    naming = _FakeNamingGateway()
    use_case = RenameUseCase(naming, _FakeDatabaseGateway())

    result = use_case.execute(RenameCommand(address="0x401000", name="  parse  "))

    # Leading/trailing whitespace is trimmed before the gateway is touched.
    assert naming.calls == [(0x401000, "parse")]
    assert result.renaming.name == "parse"


# --------------------------------------------------------------------------- #
# Use-case: rejected inputs (become isError at the boundary)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("bad_name", ["", "   ", "\t\n"])
def test_use_case_rejects_empty_or_blank_name_without_touching_gateway(bad_name):
    naming = _FakeNamingGateway()
    use_case = RenameUseCase(naming, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(RenameCommand(address="0x401000", name=bad_name))

    # A pure validation failure never reaches the database or the write.
    assert naming.calls == []


def test_use_case_propagates_gateway_name_clash():
    naming = _FakeNamingGateway(reserved={"main"})
    use_case = RenameUseCase(naming, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(RenameCommand(address="0x401000", name="main"))

    # The clash was refused by the gateway; nothing was recorded as written.
    assert naming.calls == []


def test_use_case_propagates_unresolvable_symbol():
    naming = _FakeNamingGateway()
    # No symbol table entry — resolution fails before any write.
    use_case = RenameUseCase(naming, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(RenameCommand(address="nonexistent_symbol", name="foo"))

    assert naming.calls == []


# --------------------------------------------------------------------------- #
# View projection
# --------------------------------------------------------------------------- #


def test_view_projects_rename_to_wire_shape():
    view = rename_view(
        Renaming(address=Address(0x401000), old_name="sub_401000", name="parse_header")
    )

    assert view == {
        "address": "0x401000",
        "old_name": "sub_401000",
        "name": "parse_header",
        "ok": True,
    }


def test_view_carries_empty_old_name_through():
    view = rename_view(
        Renaming(address=Address(0x14000A), old_name="", name="handler")
    )

    assert view["old_name"] == ""
    assert view["name"] == "handler"
    assert view["address"] == "0x14000a"
    assert view["ok"] is True


# --------------------------------------------------------------------------- #
# Registered tool: annotations, invocation, and isError translation
# --------------------------------------------------------------------------- #


def _register(use_case: RenameUseCase) -> Registry:
    registry = Registry()
    register_rename(registry, rename_use_case=use_case, executor=InlineExecutor())
    return registry


def test_tool_is_advertised_as_mutating():
    registry = _register(RenameUseCase(_FakeNamingGateway(), _FakeDatabaseGateway()))

    spec = registry.get_tool("rename")
    assert spec is not None
    # ``@registry.mutating`` flips the default read-only advertisement off.
    assert spec.annotations["readOnlyHint"] is False


def test_tool_invocation_returns_view_with_old_and_new_name():
    naming = _FakeNamingGateway(prior={0x401000: "sub_401000"})
    spec = _register(RenameUseCase(naming, _FakeDatabaseGateway())).get_tool("rename")

    result = spec.invoke(address="0x401000", name="parse_header")

    assert result == {
        "address": "0x401000",
        "old_name": "sub_401000",
        "name": "parse_header",
        "ok": True,
    }


def test_tool_invocation_surfaces_invalid_name_as_tool_error():
    spec = _register(
        RenameUseCase(_FakeNamingGateway(), _FakeDatabaseGateway())
    ).get_tool("rename")

    # A blank name is a per-call failure (isError), not a protocol fault.
    with pytest.raises(ToolError):
        spec.invoke(address="0x401000", name="   ")


def test_tool_invocation_surfaces_name_clash_as_tool_error():
    naming = _FakeNamingGateway(reserved={"main"})
    spec = _register(RenameUseCase(naming, _FakeDatabaseGateway())).get_tool("rename")

    with pytest.raises(ToolError):
        spec.invoke(address="0x401000", name="main")
