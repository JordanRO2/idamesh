"""Unit tests for the ``declare_stack`` and ``delete_stack`` mutation tools (no IDA).

Fake :class:`StackGateway` and resolver-backed :class:`DatabaseGateway`
implementations stand in for the IDA adapter, so the whole write path is exercised
off-host: each use-case validates the variable name (and, for a declare, the C
type), resolves a polymorphic ``function`` selector, routes the change through the
shared stack gateway, and wraps the outcome; the ``DeclareStackView`` /
``DeleteStackView`` project the completed change; and the registered tools marshal
through the executor with write affinity, advertise ``readOnlyHint: false`` (and,
for ``delete_stack``, ``destructiveHint: true``), and turn a refused declare/delete
— including an out-of-function target — into an ``isError`` (``ToolError``) instead
of a crash.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, TypeVar

import pytest

from idamesh.application.contexts.stack import (
    DeclareStackUseCase,
    DeleteStackUseCase,
)
from idamesh.application.dto.stack import (
    DeclareStackCommand,
    DeclareStackResult,
    DeleteStackCommand,
    DeleteStackResult,
)
from idamesh.domain.entities.stack_variable import (
    StackVariableDefinition,
    StackVariableDeletion,
)
from idamesh.domain.values.address import Address, Selector
from idamesh.interface.catalog.declare_stack import (
    declare_stack_view,
    register_declare_stack,
)
from idamesh.interface.catalog.delete_stack import (
    delete_stack_view,
    register_delete_stack,
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
class _Declared:
    """One recorded frame-variable definition the gateway saw."""

    func: Address
    name: str
    type: str
    offset: int


@dataclass(frozen=True)
class _Deleted:
    """One recorded frame-variable removal the gateway saw."""

    func: Address
    name: str


class _FakeStackGateway:
    """An in-memory ``StackGateway`` that records edits and can refuse them.

    ``no_function`` is the set of EAs that name no function, so a declare or delete
    there raises exactly as the adapter does when ``ida_funcs.get_func`` returns
    ``None`` — the out-of-function case. ``unplaceable`` is the set of EAs where a
    declare cannot place the variable (a type the frame refuses), and ``absent`` is
    the set of names a delete does not find on the frame. Every call is recorded
    first so a test can assert the resolved EA and the arguments that reached the
    SDK boundary.
    """

    def __init__(
        self,
        *,
        no_function: frozenset[int] = frozenset(),
        unplaceable: frozenset[int] = frozenset(),
        absent: frozenset[str] = frozenset(),
    ) -> None:
        self._no_function = no_function
        self._unplaceable = unplaceable
        self._absent = absent
        self.declared: list[_Declared] = []
        self.deleted: list[_Deleted] = []

    def declare(self, func: Address, name: str, type: str, offset: int) -> None:
        self.declared.append(_Declared(func=func, name=name, type=type, offset=offset))
        if int(func) in self._no_function:
            raise ValueError(f"no function at {func.hex()}")
        if int(func) in self._unplaceable:
            raise ValueError(
                f"cannot define stack variable {name!r} at offset {offset}"
            )

    def delete(self, func: Address, name: str) -> None:
        self.deleted.append(_Deleted(func=func, name=name))
        if int(func) in self._no_function:
            raise ValueError(f"no function at {func.hex()}")
        if name in self._absent:
            raise ValueError(
                f"the function at {func.hex()} has no stack variable {name!r}"
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


# -- declare use-case: resolution & forwarding ------------------------------


def test_declare_forwards_resolved_ea_name_type_and_offset():
    ea = 0x401000
    gateway = _FakeStackGateway()
    use_case = DeclareStackUseCase(gateway, _FakeDatabase())

    result = use_case.execute(
        DeclareStackCommand(
            function="0x401000", name="counter", type="int", offset=-0x18
        )
    )

    assert isinstance(result, DeclareStackResult)
    assert gateway.declared == [
        _Declared(func=Address(ea), name="counter", type="int", offset=-0x18)
    ]
    definition = result.definition
    assert isinstance(definition, StackVariableDefinition)
    assert definition.function == Address(ea)
    assert definition.name == "counter"


def test_declare_defaults_offset_to_zero():
    gateway = _FakeStackGateway()
    use_case = DeclareStackUseCase(gateway, _FakeDatabase())

    use_case.execute(DeclareStackCommand(function="0x401000", name="v", type="int"))

    assert gateway.declared[0].offset == 0


def test_declare_strips_name_and_type_before_forwarding():
    gateway = _FakeStackGateway()
    use_case = DeclareStackUseCase(gateway, _FakeDatabase())

    result = use_case.execute(
        DeclareStackCommand(
            function="0x401000", name="  buf  ", type="  char[16]  ", offset=-0x20
        )
    )

    # The gateway sees the trimmed name and type, and the trimmed name is reported.
    recorded = gateway.declared[0]
    assert recorded.name == "buf"
    assert recorded.type == "char[16]"
    assert result.definition.name == "buf"


def test_declare_resolves_symbol_and_decimal_selectors():
    sym_ea = 0x406060
    gateway = _FakeStackGateway()
    database = _FakeDatabase(symbols={"handler": sym_ea})
    use_case = DeclareStackUseCase(gateway, database)

    dec = use_case.execute(
        DeclareStackCommand(function="4198400", name="a", type="int")  # 0x401000
    )
    assert dec.definition.function == Address(0x401000)

    sym = use_case.execute(
        DeclareStackCommand(function="handler", name="b", type="int")
    )
    assert sym.definition.function == Address(sym_ea)
    assert gateway.declared[-1].func == Address(sym_ea)


# -- declare use-case: input guards -----------------------------------------


@pytest.mark.parametrize("blank", ["", "   ", "\t", "\n  \n"])
def test_declare_empty_or_blank_name_raises_before_gateway(blank: str):
    gateway = _FakeStackGateway()
    use_case = DeclareStackUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(
            DeclareStackCommand(function="0x401000", name=blank, type="int")
        )
    assert gateway.declared == []


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_declare_empty_or_blank_type_raises_before_gateway(blank: str):
    gateway = _FakeStackGateway()
    use_case = DeclareStackUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(
            DeclareStackCommand(function="0x401000", name="v", type=blank)
        )
    assert gateway.declared == []


def test_declare_non_string_name_or_type_raises():
    gateway = _FakeStackGateway()
    use_case = DeclareStackUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(
            DeclareStackCommand(function="0x401000", name=123, type="int")  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError):
        use_case.execute(
            DeclareStackCommand(function="0x401000", name="v", type=object())  # type: ignore[arg-type]
        )
    assert gateway.declared == []


# -- declare use-case: failure paths ----------------------------------------


def test_declare_out_of_function_propagates():
    orphan = 0x600100
    gateway = _FakeStackGateway(no_function=frozenset({orphan}))
    use_case = DeclareStackUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(
            DeclareStackCommand(function=hex(orphan), name="v", type="int")
        )


def test_declare_unplaceable_variable_propagates():
    ea = 0x401000
    gateway = _FakeStackGateway(unplaceable=frozenset({ea}))
    use_case = DeclareStackUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(DeclareStackCommand(function=hex(ea), name="v", type="int"))


def test_declare_unresolvable_symbol_raises_and_skips_gateway():
    gateway = _FakeStackGateway()
    use_case = DeclareStackUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(DeclareStackCommand(function="missing", name="v", type="int"))
    assert gateway.declared == []  # resolution fails before any write


# -- delete use-case: resolution & forwarding -------------------------------


def test_delete_forwards_resolved_ea_and_name():
    ea = 0x401000
    gateway = _FakeStackGateway()
    use_case = DeleteStackUseCase(gateway, _FakeDatabase())

    result = use_case.execute(
        DeleteStackCommand(function="0x401000", name="counter")
    )

    assert isinstance(result, DeleteStackResult)
    assert gateway.deleted == [_Deleted(func=Address(ea), name="counter")]
    deletion = result.deletion
    assert isinstance(deletion, StackVariableDeletion)
    assert deletion.function == Address(ea)
    assert deletion.name == "counter"


def test_delete_strips_name_before_forwarding():
    gateway = _FakeStackGateway()
    use_case = DeleteStackUseCase(gateway, _FakeDatabase())

    result = use_case.execute(DeleteStackCommand(function="0x401000", name="  v  "))

    assert gateway.deleted[0].name == "v"
    assert result.deletion.name == "v"


def test_delete_resolves_symbol_selector_before_writing():
    sym_ea = 0x401000
    gateway = _FakeStackGateway()
    database = _FakeDatabase(symbols={"main": sym_ea})
    use_case = DeleteStackUseCase(gateway, database)

    result = use_case.execute(DeleteStackCommand(function="main", name="v"))

    assert gateway.deleted == [_Deleted(func=Address(sym_ea), name="v")]
    assert result.deletion.function == Address(sym_ea)


# -- delete use-case: input guards & failure paths --------------------------


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_delete_empty_or_blank_name_raises_before_gateway(blank: str):
    gateway = _FakeStackGateway()
    use_case = DeleteStackUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(DeleteStackCommand(function="0x401000", name=blank))
    assert gateway.deleted == []


def test_delete_out_of_function_propagates():
    orphan = 0x600100
    gateway = _FakeStackGateway(no_function=frozenset({orphan}))
    use_case = DeleteStackUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(DeleteStackCommand(function=hex(orphan), name="v"))


def test_delete_absent_variable_propagates():
    gateway = _FakeStackGateway(absent=frozenset({"ghost"}))
    use_case = DeleteStackUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(DeleteStackCommand(function="0x401000", name="ghost"))


def test_delete_unresolvable_symbol_raises_and_skips_gateway():
    gateway = _FakeStackGateway()
    use_case = DeleteStackUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(DeleteStackCommand(function="missing", name="v"))
    assert gateway.deleted == []


# -- views ------------------------------------------------------------------


def test_declare_view_projects_definition_to_flat_shape():
    view = declare_stack_view(
        StackVariableDefinition(function=Address(0x401000), name="counter")
    )

    assert view == {
        "function": "0x401000",
        "name": "counter",
        "ok": True,
    }


def test_delete_view_projects_deletion_to_flat_shape():
    view = delete_stack_view(
        StackVariableDeletion(function=Address(0x14000A), name="buf")
    )

    assert view == {
        "function": "0x14000a",
        "name": "buf",
        "ok": True,
    }


# -- catalog registration ---------------------------------------------------


def _register_declare(gateway, database, executor) -> Registry:
    registry = Registry()
    register_declare_stack(
        registry,
        declare_stack_use_case=DeclareStackUseCase(gateway, database),
        executor=executor,
    )
    return registry


def _register_delete(gateway, database, executor) -> Registry:
    registry = Registry()
    register_delete_stack(
        registry,
        delete_stack_use_case=DeleteStackUseCase(gateway, database),
        executor=executor,
    )
    return registry


def test_declare_tool_is_advertised_as_mutating():
    registry = _register_declare(_FakeStackGateway(), _FakeDatabase(), _InlineExecutor())

    spec = registry.get_tool("declare_stack")
    assert spec is not None
    assert spec.annotations["readOnlyHint"] is False
    # Defining a frame variable is not flagged destructive.
    assert "destructiveHint" not in spec.annotations


def test_delete_tool_is_advertised_as_destructive():
    registry = _register_delete(_FakeStackGateway(), _FakeDatabase(), _InlineExecutor())

    spec = registry.get_tool("delete_stack")
    assert spec is not None
    # ``@registry.destructive`` sets both hints — it discards a frame variable.
    assert spec.annotations["readOnlyHint"] is False
    assert spec.annotations["destructiveHint"] is True


def test_declare_tool_invocation_writes_through_gateway_with_write_affinity():
    ea = 0x401000
    gateway = _FakeStackGateway()
    executor = _InlineExecutor()
    registry = _register_declare(gateway, _FakeDatabase(), executor)

    view = registry.get_tool("declare_stack").invoke(
        function="0x401000", name="  counter  ", type="int", offset=-0x18
    )

    assert view == {
        "function": "0x401000",
        "name": "counter",
        "ok": True,
    }
    # The trimmed name/type and the offset reached the gateway at the resolved EA.
    assert gateway.declared == [
        _Declared(func=Address(ea), name="counter", type="int", offset=-0x18)
    ]
    # The mutation was marshalled with explicit write affinity.
    assert executor.write_flags == [True]


def test_declare_tool_invocation_defaults_offset_to_zero():
    gateway = _FakeStackGateway()
    registry = _register_declare(gateway, _FakeDatabase(), _InlineExecutor())

    registry.get_tool("declare_stack").invoke(
        function="0x401000", name="v", type="int"
    )

    assert gateway.declared[0].offset == 0


def test_delete_tool_invocation_writes_through_gateway_with_write_affinity():
    ea = 0x401000
    gateway = _FakeStackGateway()
    executor = _InlineExecutor()
    registry = _register_delete(gateway, _FakeDatabase(), executor)

    view = registry.get_tool("delete_stack").invoke(
        function="0x401000", name="counter"
    )

    assert view == {
        "function": "0x401000",
        "name": "counter",
        "ok": True,
    }
    assert gateway.deleted == [_Deleted(func=Address(ea), name="counter")]
    assert executor.write_flags == [True]


def test_declare_tool_invocation_surfaces_out_of_function_as_toolerror():
    orphan = 0x600100
    gateway = _FakeStackGateway(no_function=frozenset({orphan}))
    registry = _register_declare(gateway, _FakeDatabase(), _InlineExecutor())

    with pytest.raises(ToolError):
        registry.get_tool("declare_stack").invoke(
            function=hex(orphan), name="v", type="int"
        )


def test_declare_tool_invocation_surfaces_blank_name_as_toolerror():
    registry = _register_declare(_FakeStackGateway(), _FakeDatabase(), _InlineExecutor())

    with pytest.raises(ToolError):
        registry.get_tool("declare_stack").invoke(
            function="0x401000", name="   ", type="int"
        )


def test_declare_tool_invocation_surfaces_unresolvable_function_as_toolerror():
    registry = _register_declare(_FakeStackGateway(), _FakeDatabase(), _InlineExecutor())

    with pytest.raises(ToolError):
        registry.get_tool("declare_stack").invoke(
            function="ghost", name="v", type="int"
        )


def test_delete_tool_invocation_surfaces_absent_variable_as_toolerror():
    gateway = _FakeStackGateway(absent=frozenset({"ghost"}))
    registry = _register_delete(gateway, _FakeDatabase(), _InlineExecutor())

    with pytest.raises(ToolError):
        registry.get_tool("delete_stack").invoke(function="0x401000", name="ghost")


def test_delete_tool_invocation_surfaces_out_of_function_as_toolerror():
    orphan = 0x600100
    gateway = _FakeStackGateway(no_function=frozenset({orphan}))
    registry = _register_delete(gateway, _FakeDatabase(), _InlineExecutor())

    with pytest.raises(ToolError):
        registry.get_tool("delete_stack").invoke(function=hex(orphan), name="v")


def test_delete_tool_invocation_surfaces_unresolvable_function_as_toolerror():
    registry = _register_delete(_FakeStackGateway(), _FakeDatabase(), _InlineExecutor())

    with pytest.raises(ToolError):
        registry.get_tool("delete_stack").invoke(function="ghost", name="v")
