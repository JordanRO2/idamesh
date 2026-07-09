"""Unit tests for the ``set_comment`` mutation tool (no IDA).

A fake :class:`CommentGateway` and a resolver-backed fake database stand in for
the IDA adapter, so the use-case's selector resolution and slot-selection policy,
the wire projection, and the catalog registration (mutating annotation, write
marshalling, error surfacing) are exercised without a database. The fake gateway
records every write and can refuse one — mirroring the real adapter refusing a
function comment where no function owns the address.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, TypeVar

import pytest

from idamesh.application.contexts.set_comment import SetCommentUseCase
from idamesh.application.dto.set_comment import (
    SetCommentCommand,
    SetCommentResult,
)
from idamesh.domain.entities.comment import CommentEdit
from idamesh.domain.values.address import Address, Selector
from idamesh.interface.catalog.set_comment import (
    register_set_comment,
    set_comment_view,
)
from idamesh.interface.mcp.engine import ToolError
from idamesh.interface.mcp.registry import Registry

T = TypeVar("T")


# -- fakes ------------------------------------------------------------------


class _FakeDatabase:
    """A resolver-backed database gateway over a fixed symbol table."""

    def __init__(self, symbols: dict[str, int] | None = None) -> None:
        self._symbols = symbols or {}

    def resolve_symbol(self, name: str) -> int | None:
        return self._symbols.get(name)

    def resolve(self, selector: Selector) -> Address:
        # Mirror the real gateway: numeric kinds parse directly, symbols look up.
        return selector.resolve(self)


@dataclass(frozen=True)
class _Write:
    """One recorded comment write."""

    ea: Address
    comment: str
    repeatable: bool
    function: bool


class _FakeCommentGateway:
    """An in-memory ``CommentGateway`` that records writes and can refuse them.

    Addresses in ``functions`` are treated as belonging to a function; a function
    comment requested elsewhere raises, exactly as the IDA adapter does when
    ``ida_funcs.get_func`` returns ``None``.
    """

    def __init__(self, functions: set[int] | None = None) -> None:
        self._functions = functions
        self.writes: list[_Write] = []

    def set_comment(
        self,
        ea: Address,
        comment: str,
        *,
        repeatable: bool,
        function: bool,
    ) -> None:
        if function and self._functions is not None and int(ea) not in self._functions:
            raise ValueError(
                f"no function contains {ea.hex()}: cannot set a function comment"
            )
        self.writes.append(
            _Write(ea=ea, comment=comment, repeatable=repeatable, function=function)
        )


class _InlineExecutor:
    """A ``MainThreadExecutor`` that runs jobs inline, recording write affinity."""

    def __init__(self) -> None:
        self.write_flags: list[bool] = []

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        self.write_flags.append(write)
        return job()

    def on_kernel_thread(self) -> bool:
        return True


# -- use-case: slot selection & resolution ----------------------------------


def test_item_comment_written_to_anchored_slot_by_default():
    ea = 0x401000
    gateway = _FakeCommentGateway()
    use_case = SetCommentUseCase(gateway, _FakeDatabase())

    result = use_case.execute(
        SetCommentCommand(address="0x401000", comment="loop header")
    )

    assert isinstance(result, SetCommentResult)
    assert gateway.writes == [
        _Write(Address(ea), "loop header", repeatable=False, function=False)
    ]
    edit = result.edit
    assert isinstance(edit, CommentEdit)
    assert edit.address == Address(ea)
    assert edit.comment == "loop header"
    assert edit.repeatable is False
    assert edit.function is False


def test_function_flag_routes_to_function_comment():
    ea = 0x402000
    gateway = _FakeCommentGateway(functions={ea})
    use_case = SetCommentUseCase(gateway, _FakeDatabase())

    result = use_case.execute(
        SetCommentCommand(address=hex(ea), comment="decodes the header", function=True)
    )

    assert gateway.writes[0].function is True
    assert gateway.writes[0].comment == "decodes the header"
    assert result.edit.function is True


def test_repeatable_flag_selects_repeatable_slot():
    ea = 0x403000
    gateway = _FakeCommentGateway()
    use_case = SetCommentUseCase(gateway, _FakeDatabase())

    result = use_case.execute(
        SetCommentCommand(address=hex(ea), comment="global config", repeatable=True)
    )

    assert gateway.writes[0].repeatable is True
    assert result.edit.repeatable is True
    assert result.edit.function is False


def test_repeatable_and_function_flags_combine():
    ea = 0x404000
    gateway = _FakeCommentGateway(functions={ea})
    use_case = SetCommentUseCase(gateway, _FakeDatabase())

    result = use_case.execute(
        SetCommentCommand(
            address=hex(ea), comment="thunk", repeatable=True, function=True
        )
    )

    write = gateway.writes[0]
    assert (write.repeatable, write.function) == (True, True)
    assert (result.edit.repeatable, result.edit.function) == (True, True)


def test_empty_comment_clears_slot_and_is_ok():
    ea = 0x405000
    gateway = _FakeCommentGateway()
    use_case = SetCommentUseCase(gateway, _FakeDatabase())

    result = use_case.execute(SetCommentCommand(address=hex(ea), comment=""))

    # Emptiness is a valid clear operation, not a validation error.
    assert gateway.writes[0].comment == ""
    assert result.edit.comment == ""


def test_resolves_decimal_and_symbol_addresses():
    sym_ea = 0x406060
    gateway = _FakeCommentGateway()
    database = _FakeDatabase(symbols={"handler": sym_ea})
    use_case = SetCommentUseCase(gateway, database)

    dec = use_case.execute(SetCommentCommand(address="4218880", comment="dec"))
    assert dec.edit.address == Address(4218880)

    sym = use_case.execute(SetCommentCommand(address="handler", comment="sym"))
    assert sym.edit.address == Address(sym_ea)
    assert gateway.writes[-1].ea == Address(sym_ea)


def test_unresolvable_symbol_raises():
    use_case = SetCommentUseCase(_FakeCommentGateway(), _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(SetCommentCommand(address="nope", comment="x"))


def test_function_comment_where_no_function_propagates_error():
    orphan = 0x600100
    gateway = _FakeCommentGateway(functions={0x401000})  # orphan not a function
    use_case = SetCommentUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(
            SetCommentCommand(address=hex(orphan), comment="x", function=True)
        )
    assert gateway.writes == []  # nothing recorded on refusal


# -- view -------------------------------------------------------------------


def test_view_projects_edit_to_flat_shape():
    edit = CommentEdit(
        address=Address(0x401000),
        comment="loop header",
        repeatable=False,
        function=False,
    )

    view = set_comment_view(edit)

    assert view == {
        "address": "0x401000",
        "comment": "loop header",
        "ok": True,
    }


def test_view_reports_ok_true_for_cleared_slot():
    edit = CommentEdit(
        address=Address(0x402000), comment="", repeatable=True, function=True
    )

    view = set_comment_view(edit)

    assert view["comment"] == ""
    assert view["ok"] is True
    assert view["address"] == "0x402000"


# -- catalog registration ---------------------------------------------------


def _register(gateway: _FakeCommentGateway, database: _FakeDatabase, executor):
    registry = Registry()
    register_set_comment(
        registry,
        set_comment_use_case=SetCommentUseCase(gateway, database),
        executor=executor,
    )
    return registry


def test_tool_is_registered_as_mutating():
    registry = _register(_FakeCommentGateway(), _FakeDatabase(), _InlineExecutor())

    spec = registry.get_tool("set_comment")
    assert spec is not None
    assert spec.annotations["readOnlyHint"] is False
    # A comment write replaces an annotation, not user data — not destructive.
    assert "destructiveHint" not in spec.annotations


def test_tool_invocation_writes_through_gateway_with_write_affinity():
    ea = 0x401000
    gateway = _FakeCommentGateway()
    executor = _InlineExecutor()
    registry = _register(gateway, _FakeDatabase(), executor)

    invoke = registry.get_tool("set_comment").invoke
    view = invoke(address="0x401000", comment="entry")

    assert view == {"address": "0x401000", "comment": "entry", "ok": True}
    assert gateway.writes == [
        _Write(Address(ea), "entry", repeatable=False, function=False)
    ]
    # The mutation was marshalled with explicit write affinity.
    assert executor.write_flags == [True]


def test_tool_invocation_forwards_optional_flags():
    ea = 0x402000
    gateway = _FakeCommentGateway(functions={ea})
    registry = _register(gateway, _FakeDatabase(), _InlineExecutor())

    invoke = registry.get_tool("set_comment").invoke
    invoke(address=hex(ea), comment="fn", repeatable=True, function=True)

    write = gateway.writes[0]
    assert (write.repeatable, write.function) == (True, True)


def test_tool_invocation_surfaces_gateway_refusal_as_toolerror():
    orphan = 0x600100
    gateway = _FakeCommentGateway(functions={0x401000})
    registry = _register(gateway, _FakeDatabase(), _InlineExecutor())

    invoke = registry.get_tool("set_comment").invoke
    with pytest.raises(ToolError):
        invoke(address=hex(orphan), comment="x", function=True)


def test_tool_invocation_surfaces_unresolvable_address_as_toolerror():
    registry = _register(_FakeCommentGateway(), _FakeDatabase(), _InlineExecutor())

    invoke = registry.get_tool("set_comment").invoke
    with pytest.raises(ToolError):
        invoke(address="ghost", comment="x")
