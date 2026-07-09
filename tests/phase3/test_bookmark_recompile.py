"""Unit tests for the ``add_bookmark`` and ``force_recompile`` tools (no IDA).

Fake :class:`BookmarkGateway`, :class:`RecompileGateway`, and
:class:`DatabaseGateway` implementations stand in for the IDA adapters, so the
whole write path is exercised off-host: each use-case resolves a polymorphic
selector, ``add_bookmark`` also validates a non-empty description before routing
the mark through the bookmark gateway (which reports the slot), and
``force_recompile`` routes the cache invalidation through the recompile gateway;
the ``AddBookmarkView`` / ``ForceRecompileView`` project the completed change; and
the registered tools marshal through the executor, advertise ``readOnlyHint:
false`` (neither is destructive), and turn a rejected description, a refusing
gateway, or an unresolvable address into an ``isError`` (``ToolError``) instead of
a crash.
"""

from __future__ import annotations

import pytest

from idamesh.application.contexts.add_bookmark import AddBookmarkUseCase
from idamesh.application.contexts.force_recompile import ForceRecompileUseCase
from idamesh.application.dto.add_bookmark import AddBookmarkCommand
from idamesh.application.dto.force_recompile import ForceRecompileCommand
from idamesh.domain.entities.bookmark import Bookmark
from idamesh.domain.entities.recompilation import Recompilation
from idamesh.domain.values.address import Address, Selector
from idamesh.infrastructure.execution.inline import InlineExecutor
from idamesh.interface.catalog.add_bookmark import (
    add_bookmark_view,
    register_add_bookmark,
)
from idamesh.interface.catalog.force_recompile import (
    force_recompile_view,
    register_force_recompile,
)
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


class _FakeBookmarkGateway:
    """In-memory bookmark gateway: allocates slots, reuses per address, refuses.

    ``existing`` seeds addresses already bookmarked to a fixed slot, so re-marking
    one returns the same slot (mirroring the adapter's slot-reuse scan). Fresh
    addresses claim ascending slots starting at 1. ``refuse`` is the set of EAs the
    database cannot bookmark, so a write there raises — mirroring the adapter
    surfacing a full table or a non-persisting write as a domain error.
    """

    def __init__(
        self,
        existing: dict[int, int] | None = None,
        refuse: set[int] | None = None,
    ) -> None:
        self._slots = dict(existing or {})
        self._refuse = set(refuse or set())
        self.calls: list[tuple[int, str]] = []

    def add(self, ea: Address, description: str) -> int:
        addr = int(ea)
        if addr in self._refuse:
            raise ValueError(f"cannot bookmark {ea.hex()}: no free slot")
        self.calls.append((addr, description))
        if addr in self._slots:
            return self._slots[addr]
        slot = 1
        used = set(self._slots.values())
        while slot in used:
            slot += 1
        self._slots[addr] = slot
        return slot


class _FakeRecompileGateway:
    """In-memory recompile gateway: records invalidations, models refusals.

    ``refuse`` is the set of EAs for which the invalidation cannot proceed — an
    address in no function, or an unavailable decompiler — so a call there raises,
    mirroring the adapter surfacing those SDK failures as a domain error.
    """

    def __init__(self, refuse: set[int] | None = None) -> None:
        self._refuse = set(refuse or set())
        self.calls: list[int] = []

    def recompile(self, ea: Address) -> None:
        if int(ea) in self._refuse:
            raise ValueError(f"{ea.hex()} is not inside a function")
        self.calls.append(int(ea))


# --------------------------------------------------------------------------- #
# add_bookmark use-case: happy path
# --------------------------------------------------------------------------- #


def test_add_bookmark_use_case_marks_address_and_reports_slot():
    bookmarks = _FakeBookmarkGateway()
    use_case = AddBookmarkUseCase(bookmarks, _FakeDatabaseGateway())

    result = use_case.execute(
        AddBookmarkCommand(address="0x401000", description="parse loop")
    )

    bookmark = result.bookmark
    assert isinstance(bookmark, Bookmark)
    assert bookmark.address == Address(0x401000)
    assert bookmark.slot == 1
    # The gateway saw exactly one mark, at the resolved EA, with the description.
    assert bookmarks.calls == [(0x401000, "parse loop")]


def test_add_bookmark_use_case_assigns_distinct_slots_to_distinct_addresses():
    bookmarks = _FakeBookmarkGateway()
    use_case = AddBookmarkUseCase(bookmarks, _FakeDatabaseGateway())

    first = use_case.execute(
        AddBookmarkCommand(address="0x401000", description="a")
    )
    second = use_case.execute(
        AddBookmarkCommand(address="0x402000", description="b")
    )

    assert first.bookmark.slot == 1
    assert second.bookmark.slot == 2


def test_add_bookmark_use_case_reuses_slot_for_already_marked_address():
    # 0x401000 is already bookmarked in slot 7; re-marking must reuse it.
    bookmarks = _FakeBookmarkGateway(existing={0x401000: 7})
    use_case = AddBookmarkUseCase(bookmarks, _FakeDatabaseGateway())

    result = use_case.execute(
        AddBookmarkCommand(address="0x401000", description="updated")
    )

    assert result.bookmark.slot == 7
    assert bookmarks.calls == [(0x401000, "updated")]


def test_add_bookmark_use_case_resolves_symbol_selector_before_marking():
    bookmarks = _FakeBookmarkGateway()
    database = _FakeDatabaseGateway(symbols={"parse_header": 0x401000})
    use_case = AddBookmarkUseCase(bookmarks, database)

    result = use_case.execute(
        AddBookmarkCommand(address="parse_header", description="here")
    )

    # The symbol name was resolved to its EA, and the mark targeted that EA.
    assert bookmarks.calls == [(0x401000, "here")]
    assert result.bookmark.address == Address(0x401000)


def test_add_bookmark_use_case_resolves_decimal_selector():
    bookmarks = _FakeBookmarkGateway()
    use_case = AddBookmarkUseCase(bookmarks, _FakeDatabaseGateway())

    use_case.execute(
        AddBookmarkCommand(address="4198400", description="d")  # 0x401000
    )

    assert bookmarks.calls == [(0x401000, "d")]


def test_add_bookmark_use_case_strips_surrounding_whitespace_from_description():
    bookmarks = _FakeBookmarkGateway()
    use_case = AddBookmarkUseCase(bookmarks, _FakeDatabaseGateway())

    use_case.execute(
        AddBookmarkCommand(address="0x401000", description="  note  ")
    )

    # Leading/trailing whitespace is trimmed before the gateway is touched.
    assert bookmarks.calls == [(0x401000, "note")]


# --------------------------------------------------------------------------- #
# add_bookmark use-case: rejected inputs (become isError at the boundary)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("bad_description", ["", "   ", "\t\n"])
def test_add_bookmark_use_case_rejects_blank_description_without_touching_gateway(
    bad_description,
):
    bookmarks = _FakeBookmarkGateway()
    use_case = AddBookmarkUseCase(bookmarks, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(
            AddBookmarkCommand(address="0x401000", description=bad_description)
        )

    # A pure validation failure never reaches the database or the write.
    assert bookmarks.calls == []


def test_add_bookmark_use_case_propagates_gateway_refusal():
    bookmarks = _FakeBookmarkGateway(refuse={0x401000})
    use_case = AddBookmarkUseCase(bookmarks, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(
            AddBookmarkCommand(address="0x401000", description="x")
        )

    # The refusal happened at the gateway; nothing was recorded as marked.
    assert bookmarks.calls == []


def test_add_bookmark_use_case_propagates_unresolvable_symbol():
    bookmarks = _FakeBookmarkGateway()
    # No symbol table entry — resolution fails before any write.
    use_case = AddBookmarkUseCase(bookmarks, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(
            AddBookmarkCommand(address="nonexistent_symbol", description="x")
        )

    assert bookmarks.calls == []


# --------------------------------------------------------------------------- #
# force_recompile use-case: happy path
# --------------------------------------------------------------------------- #


def test_force_recompile_use_case_invalidates_at_resolved_address():
    recompiler = _FakeRecompileGateway()
    use_case = ForceRecompileUseCase(recompiler, _FakeDatabaseGateway())

    result = use_case.execute(ForceRecompileCommand(address="0x401000"))

    recompilation = result.recompilation
    assert isinstance(recompilation, Recompilation)
    assert recompilation.address == Address(0x401000)
    assert recompiler.calls == [0x401000]


def test_force_recompile_use_case_resolves_symbol_selector_before_invalidating():
    recompiler = _FakeRecompileGateway()
    database = _FakeDatabaseGateway(symbols={"sub_401000": 0x401000})
    use_case = ForceRecompileUseCase(recompiler, database)

    result = use_case.execute(ForceRecompileCommand(address="sub_401000"))

    assert recompiler.calls == [0x401000]
    assert result.recompilation.address == Address(0x401000)


def test_force_recompile_use_case_resolves_decimal_selector():
    recompiler = _FakeRecompileGateway()
    use_case = ForceRecompileUseCase(recompiler, _FakeDatabaseGateway())

    use_case.execute(ForceRecompileCommand(address="4198400"))  # 0x401000

    assert recompiler.calls == [0x401000]


# --------------------------------------------------------------------------- #
# force_recompile use-case: rejected inputs (become isError at the boundary)
# --------------------------------------------------------------------------- #


def test_force_recompile_use_case_propagates_address_in_no_function():
    recompiler = _FakeRecompileGateway(refuse={0x401000})
    use_case = ForceRecompileUseCase(recompiler, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(ForceRecompileCommand(address="0x401000"))

    # The refusal happened at the gateway; nothing was recorded as invalidated.
    assert recompiler.calls == []


def test_force_recompile_use_case_propagates_unresolvable_symbol():
    recompiler = _FakeRecompileGateway()
    use_case = ForceRecompileUseCase(recompiler, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(ForceRecompileCommand(address="nonexistent_symbol"))

    assert recompiler.calls == []


# --------------------------------------------------------------------------- #
# View projections
# --------------------------------------------------------------------------- #


def test_add_bookmark_view_projects_bookmark_to_wire_shape():
    view = add_bookmark_view(Bookmark(address=Address(0x401000), slot=3))

    assert view == {
        "address": "0x401000",
        "slot": 3,
        "ok": True,
    }


def test_add_bookmark_view_renders_lowercase_hex_address():
    view = add_bookmark_view(Bookmark(address=Address(0x14000A), slot=1))

    assert view["address"] == "0x14000a"
    assert view["slot"] == 1
    assert view["ok"] is True


def test_force_recompile_view_projects_recompilation_to_wire_shape():
    view = force_recompile_view(Recompilation(address=Address(0x401000)))

    assert view == {
        "address": "0x401000",
        "ok": True,
    }


# --------------------------------------------------------------------------- #
# Registered tools: annotations, invocation, and isError translation
# --------------------------------------------------------------------------- #


def _register_add_bookmark(use_case: AddBookmarkUseCase) -> Registry:
    registry = Registry()
    register_add_bookmark(
        registry, add_bookmark_use_case=use_case, executor=InlineExecutor()
    )
    return registry


def _register_force_recompile(use_case: ForceRecompileUseCase) -> Registry:
    registry = Registry()
    register_force_recompile(
        registry, force_recompile_use_case=use_case, executor=InlineExecutor()
    )
    return registry


def test_add_bookmark_tool_is_advertised_as_mutating():
    registry = _register_add_bookmark(
        AddBookmarkUseCase(_FakeBookmarkGateway(), _FakeDatabaseGateway())
    )

    spec = registry.get_tool("add_bookmark")
    assert spec is not None
    # ``@registry.mutating`` flips the default read-only advertisement off.
    assert spec.annotations["readOnlyHint"] is False
    # Adding a mark is not flagged destructive.
    assert "destructiveHint" not in spec.annotations


def test_force_recompile_tool_is_advertised_as_mutating():
    registry = _register_force_recompile(
        ForceRecompileUseCase(_FakeRecompileGateway(), _FakeDatabaseGateway())
    )

    spec = registry.get_tool("force_recompile")
    assert spec is not None
    assert spec.annotations["readOnlyHint"] is False
    # Invalidating cache state is not flagged destructive.
    assert "destructiveHint" not in spec.annotations


def test_add_bookmark_tool_invocation_returns_view_with_slot():
    bookmarks = _FakeBookmarkGateway(existing={0x401000: 4})
    spec = _register_add_bookmark(
        AddBookmarkUseCase(bookmarks, _FakeDatabaseGateway())
    ).get_tool("add_bookmark")

    result = spec.invoke(address="0x401000", description="loop head")

    assert result == {
        "address": "0x401000",
        "slot": 4,
        "ok": True,
    }


def test_force_recompile_tool_invocation_returns_view():
    recompiler = _FakeRecompileGateway()
    spec = _register_force_recompile(
        ForceRecompileUseCase(recompiler, _FakeDatabaseGateway())
    ).get_tool("force_recompile")

    result = spec.invoke(address="0x401000")

    assert result == {
        "address": "0x401000",
        "ok": True,
    }
    assert recompiler.calls == [0x401000]


def test_add_bookmark_tool_invocation_surfaces_blank_description_as_tool_error():
    spec = _register_add_bookmark(
        AddBookmarkUseCase(_FakeBookmarkGateway(), _FakeDatabaseGateway())
    ).get_tool("add_bookmark")

    # A blank description is a per-call failure (isError), not a protocol fault.
    with pytest.raises(ToolError):
        spec.invoke(address="0x401000", description="   ")


def test_add_bookmark_tool_invocation_surfaces_gateway_refusal_as_tool_error():
    bookmarks = _FakeBookmarkGateway(refuse={0x401000})
    spec = _register_add_bookmark(
        AddBookmarkUseCase(bookmarks, _FakeDatabaseGateway())
    ).get_tool("add_bookmark")

    with pytest.raises(ToolError):
        spec.invoke(address="0x401000", description="x")


def test_add_bookmark_tool_invocation_surfaces_unresolvable_address_as_tool_error():
    spec = _register_add_bookmark(
        AddBookmarkUseCase(_FakeBookmarkGateway(), _FakeDatabaseGateway())
    ).get_tool("add_bookmark")

    with pytest.raises(ToolError):
        spec.invoke(address="nonexistent_symbol", description="x")


def test_force_recompile_tool_invocation_surfaces_no_function_as_tool_error():
    recompiler = _FakeRecompileGateway(refuse={0x401000})
    spec = _register_force_recompile(
        ForceRecompileUseCase(recompiler, _FakeDatabaseGateway())
    ).get_tool("force_recompile")

    with pytest.raises(ToolError):
        spec.invoke(address="0x401000")


def test_force_recompile_tool_invocation_surfaces_unresolvable_address_as_tool_error():
    spec = _register_force_recompile(
        ForceRecompileUseCase(_FakeRecompileGateway(), _FakeDatabaseGateway())
    ).get_tool("force_recompile")

    with pytest.raises(ToolError):
        spec.invoke(address="nonexistent_symbol")
