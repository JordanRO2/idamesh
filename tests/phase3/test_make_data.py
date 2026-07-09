"""Unit tests for the ``make_data`` mutation tool (no IDA).

A fake :class:`DataDefinitionGateway` and a resolver-backed fake database replace
the IDA adapter, so the use-case's type-or-size guard and selector resolution, the
wire projection, and the catalog registration (mutating annotation, write
marshalling, error surfacing) are exercised without a database. The fake gateway
records every definition and can refuse one three ways — an unparseable
declaration, an unsupported size, and an address the database will not define at —
mirroring the real adapter's ``parse_decl`` returning ``None``, an off-list size,
and ``apply_tinfo``/``create_*`` returning false respectively.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, TypeVar

import pytest

from idamesh.application.contexts.make_data import MakeDataUseCase
from idamesh.application.dto.make_data import MakeDataCommand, MakeDataResult
from idamesh.domain.entities.data_definition import DataDefinition
from idamesh.domain.values.address import Address, Selector
from idamesh.interface.catalog.make_data import make_data_view, register_make_data
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
class _Def:
    """One recorded definition (the exact ea, declaration, and size the gateway saw)."""

    ea: Address
    type: str
    size: int


class _FakeDataDefinitionGateway:
    """An in-memory ``DataDefinitionGateway`` that records defines and can refuse them.

    On success it echoes the type in force and the item's size: a typed request
    returns ``(stripped_decl, typed_size)`` and a sized request returns the
    primitive label for that width and the width itself. A declaration in
    ``unparseable`` raises as the adapter does when ``parse_decl`` fails; a size in
    ``unsupported`` raises as it does off the 1/2/4/8 list; an address in
    ``undefinable`` raises as it does when the item cannot be created there. Every
    call is recorded first so a test can assert the resolved ea and *stripped*
    declaration reached the SDK.
    """

    #: Primitive labels the real adapter reports for the native widths.
    _LABELS = {1: "byte", 2: "word", 4: "dword", 8: "qword"}

    def __init__(
        self,
        *,
        typed_size: int = 4,
        unparseable: frozenset[str] = frozenset(),
        unsupported: frozenset[int] = frozenset(),
        undefinable: frozenset[int] = frozenset(),
    ) -> None:
        self._typed_size = typed_size
        self._unparseable = unparseable
        self._unsupported = unsupported
        self._undefinable = undefinable
        self.defines: list[_Def] = []

    def make_data(self, ea: Address, type: str, size: int) -> tuple[str, int]:
        self.defines.append(_Def(ea=ea, type=type, size=size))
        if type:
            if type in self._unparseable:
                raise ValueError(f"cannot parse type declaration: {type!r}")
            if int(ea) in self._undefinable:
                raise ValueError(f"cannot define data of type {type!r} at {ea.hex()}")
            return type, self._typed_size
        if size in self._unsupported or size not in self._LABELS:
            raise ValueError(f"unsupported data size {size!r}")
        if int(ea) in self._undefinable:
            raise ValueError(f"cannot create data at {ea.hex()}")
        return self._LABELS[size], size


class _InlineExecutor:
    """A ``MainThreadExecutor`` that runs jobs inline, recording write affinity."""

    def __init__(self) -> None:
        self.write_flags: list[bool] = []

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        self.write_flags.append(write)
        return job()

    def on_kernel_thread(self) -> bool:
        return True


# -- use-case: typed path ---------------------------------------------------


def test_typed_request_forwards_resolved_ea_and_declaration():
    ea = 0x401000
    gateway = _FakeDataDefinitionGateway(typed_size=16)
    use_case = MakeDataUseCase(gateway, _FakeDatabase())

    result = use_case.execute(
        MakeDataCommand(address="0x401000", type="char[16]")
    )

    assert isinstance(result, MakeDataResult)
    # A typed request reaches the gateway with an empty size and the declaration.
    assert gateway.defines == [_Def(Address(ea), "char[16]", 0)]
    definition = result.definition
    assert isinstance(definition, DataDefinition)
    assert definition.address == Address(ea)
    assert definition.type == "char[16]"
    assert definition.size == 16


def test_declaration_is_stripped_before_reaching_gateway():
    ea = 0x402000
    gateway = _FakeDataDefinitionGateway(typed_size=4)
    use_case = MakeDataUseCase(gateway, _FakeDatabase())

    result = use_case.execute(
        MakeDataCommand(address=hex(ea), type="  int  ")
    )

    # The gateway sees the trimmed declaration, and the trimmed form is reported.
    assert gateway.defines == [_Def(Address(ea), "int", 0)]
    assert result.definition.type == "int"


# -- use-case: sized path ---------------------------------------------------


@pytest.mark.parametrize(
    "size, label",
    [(1, "byte"), (2, "word"), (4, "dword"), (8, "qword")],
)
def test_sized_request_defines_primitive_of_that_width(size: int, label: str):
    ea = 0x404000
    gateway = _FakeDataDefinitionGateway()
    use_case = MakeDataUseCase(gateway, _FakeDatabase())

    result = use_case.execute(MakeDataCommand(address=hex(ea), size=size))

    # A sized request reaches the gateway with an empty declaration and the width.
    assert gateway.defines == [_Def(Address(ea), "", size)]
    assert result.definition.type == label
    assert result.definition.size == size


def test_resolves_decimal_and_symbol_addresses():
    sym_ea = 0x406060
    gateway = _FakeDataDefinitionGateway()
    database = _FakeDatabase(symbols={"g_table": sym_ea})
    use_case = MakeDataUseCase(gateway, database)

    dec = use_case.execute(MakeDataCommand(address="4218880", size=4))
    assert dec.definition.address == Address(4218880)

    sym = use_case.execute(MakeDataCommand(address="g_table", type="int"))
    assert sym.definition.address == Address(sym_ea)
    assert gateway.defines[-1].ea == Address(sym_ea)


# -- use-case: type-or-size guard -------------------------------------------


@pytest.mark.parametrize("blank", ["", "   ", "\t", "\n  \n"])
def test_blank_type_and_zero_size_raises_before_touching_gateway(blank: str):
    gateway = _FakeDataDefinitionGateway()
    use_case = MakeDataUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(MakeDataCommand(address="0x401000", type=blank, size=0))
    # The guard runs first: neither resolution nor a define was attempted.
    assert gateway.defines == []


def test_negative_size_raises_before_touching_gateway():
    gateway = _FakeDataDefinitionGateway()
    use_case = MakeDataUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(MakeDataCommand(address="0x401000", size=-4))
    assert gateway.defines == []


def test_non_string_type_and_non_int_size_raise():
    gateway = _FakeDataDefinitionGateway()
    use_case = MakeDataUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(
            MakeDataCommand(address="0x401000", type=123)  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError):
        use_case.execute(
            MakeDataCommand(address="0x401000", size="4")  # type: ignore[arg-type]
        )
    # A bool is not an integer size (it is rejected before the gateway).
    with pytest.raises(ValueError):
        use_case.execute(
            MakeDataCommand(address="0x401000", size=True)  # type: ignore[arg-type]
        )
    assert gateway.defines == []


# -- use-case: failure paths ------------------------------------------------


def test_unparseable_declaration_propagates():
    bad = "int ((("
    gateway = _FakeDataDefinitionGateway(unparseable=frozenset({bad}))
    use_case = MakeDataUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(MakeDataCommand(address="0x401000", type=bad))


def test_unsupported_size_propagates():
    gateway = _FakeDataDefinitionGateway(unsupported=frozenset({3}))
    use_case = MakeDataUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(MakeDataCommand(address="0x401000", size=3))


def test_definition_the_database_refuses_propagates():
    orphan = 0x600100
    gateway = _FakeDataDefinitionGateway(undefinable=frozenset({orphan}))
    use_case = MakeDataUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(MakeDataCommand(address=hex(orphan), type="int"))


def test_unresolvable_symbol_raises_and_skips_define():
    gateway = _FakeDataDefinitionGateway()
    use_case = MakeDataUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(MakeDataCommand(address="missing", size=4))
    assert gateway.defines == []  # resolution fails before any define


# -- view -------------------------------------------------------------------


def test_view_projects_typed_definition_to_flat_shape():
    definition = DataDefinition(address=Address(0x401000), type="char[16]", size=16)

    view = make_data_view(definition)

    assert view == {
        "address": "0x401000",
        "type": "char[16]",
        "size": 16,
        "ok": True,
    }


def test_view_projects_primitive_definition_and_reports_ok_true():
    definition = DataDefinition(address=Address(0x402000), type="dword", size=4)

    view = make_data_view(definition)

    assert view["type"] == "dword"
    assert view["size"] == 4
    assert view["ok"] is True
    assert view["address"] == "0x402000"


# -- catalog registration ---------------------------------------------------


def _register(gateway: _FakeDataDefinitionGateway, database: _FakeDatabase, executor):
    registry = Registry()
    register_make_data(
        registry,
        make_data_use_case=MakeDataUseCase(gateway, database),
        executor=executor,
    )
    return registry


def test_tool_is_registered_as_mutating():
    registry = _register(
        _FakeDataDefinitionGateway(), _FakeDatabase(), _InlineExecutor()
    )

    spec = registry.get_tool("make_data")
    assert spec is not None
    assert spec.annotations["readOnlyHint"] is False
    # Defining data replaces raw bytes with a symbol, not user data — not destructive.
    assert "destructiveHint" not in spec.annotations


def test_tool_invocation_defines_through_gateway_with_write_affinity():
    ea = 0x401000
    gateway = _FakeDataDefinitionGateway(typed_size=16)
    executor = _InlineExecutor()
    registry = _register(gateway, _FakeDatabase(), executor)

    invoke = registry.get_tool("make_data").invoke
    view = invoke(address="0x401000", type="  char[16]  ")

    assert view == {
        "address": "0x401000",
        "type": "char[16]",
        "size": 16,
        "ok": True,
    }
    # The stripped declaration reached the gateway at the resolved address.
    assert gateway.defines == [_Def(Address(ea), "char[16]", 0)]
    # The mutation was marshalled with explicit write affinity.
    assert executor.write_flags == [True]


def test_tool_invocation_defines_primitive_by_size():
    ea = 0x404000
    gateway = _FakeDataDefinitionGateway()
    executor = _InlineExecutor()
    registry = _register(gateway, _FakeDatabase(), executor)

    invoke = registry.get_tool("make_data").invoke
    view = invoke(address="0x404000", size=8)

    assert view == {
        "address": "0x404000",
        "type": "qword",
        "size": 8,
        "ok": True,
    }
    assert gateway.defines == [_Def(Address(ea), "", 8)]
    assert executor.write_flags == [True]


def test_tool_invocation_surfaces_unparseable_type_as_toolerror():
    bad = "int ((("
    gateway = _FakeDataDefinitionGateway(unparseable=frozenset({bad}))
    registry = _register(gateway, _FakeDatabase(), _InlineExecutor())

    invoke = registry.get_tool("make_data").invoke
    with pytest.raises(ToolError):
        invoke(address="0x401000", type=bad)


def test_tool_invocation_surfaces_missing_type_and_size_as_toolerror():
    registry = _register(
        _FakeDataDefinitionGateway(), _FakeDatabase(), _InlineExecutor()
    )

    invoke = registry.get_tool("make_data").invoke
    with pytest.raises(ToolError):
        invoke(address="0x401000")


def test_tool_invocation_surfaces_unsupported_size_as_toolerror():
    gateway = _FakeDataDefinitionGateway(unsupported=frozenset({3}))
    registry = _register(gateway, _FakeDatabase(), _InlineExecutor())

    invoke = registry.get_tool("make_data").invoke
    with pytest.raises(ToolError):
        invoke(address="0x401000", size=3)


def test_tool_invocation_surfaces_unresolvable_address_as_toolerror():
    registry = _register(
        _FakeDataDefinitionGateway(), _FakeDatabase(), _InlineExecutor()
    )

    invoke = registry.get_tool("make_data").invoke
    with pytest.raises(ToolError):
        invoke(address="ghost", size=4)
