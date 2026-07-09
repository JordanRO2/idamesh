"""Unit tests for the ``set_type`` mutation tool (no IDA).

A fake :class:`TypeMutationGateway` and a resolver-backed fake database replace the
IDA adapter, so the use-case's declaration guard and selector resolution, the wire
projection, and the catalog registration (mutating annotation, write marshalling,
error surfacing) are exercised without a database. The fake gateway records every
apply and can refuse one two ways — an unparseable declaration and a type that will
not apply at the address — mirroring the real adapter's ``parse_decl`` returning
``None`` and ``apply_tinfo`` returning false respectively.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, TypeVar

import pytest

from idamesh.application.contexts.set_type import SetTypeUseCase
from idamesh.application.dto.set_type import SetTypeCommand, SetTypeResult
from idamesh.domain.entities.type_application import TypeApplication
from idamesh.domain.values.address import Address, Selector
from idamesh.interface.catalog.set_type import register_set_type, set_type_view
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
class _Apply:
    """One recorded type application (the exact ea and declaration the gateway saw)."""

    ea: Address
    decl: str


class _FakeTypeMutationGateway:
    """An in-memory ``TypeMutationGateway`` that records applies and can refuse them.

    Returns ``name`` as the retyped item's name on success (``""`` models an
    unnamed item). A declaration in ``unparseable`` raises as the adapter does when
    ``parse_decl`` fails; an address in ``unappliable`` raises as it does when
    ``apply_tinfo`` refuses the type at that ea. Every call is recorded first so a
    test can assert the resolved ea and the *stripped* declaration reached the SDK.
    """

    def __init__(
        self,
        *,
        name: str = "",
        unparseable: frozenset[str] = frozenset(),
        unappliable: frozenset[int] = frozenset(),
    ) -> None:
        self._name = name
        self._unparseable = unparseable
        self._unappliable = unappliable
        self.applies: list[_Apply] = []

    def apply_type(self, ea: Address, decl: str) -> str:
        self.applies.append(_Apply(ea=ea, decl=decl))
        if decl in self._unparseable:
            raise ValueError(f"cannot parse type declaration: {decl!r}")
        if int(ea) in self._unappliable:
            raise ValueError(f"cannot apply type {decl!r} at {ea.hex()}")
        return self._name


class _InlineExecutor:
    """A ``MainThreadExecutor`` that runs jobs inline, recording write affinity."""

    def __init__(self) -> None:
        self.write_flags: list[bool] = []

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        self.write_flags.append(write)
        return job()

    def on_kernel_thread(self) -> bool:
        return True


# -- use-case: resolution & apply -------------------------------------------


def test_apply_forwards_resolved_ea_and_declaration():
    ea = 0x401000
    gateway = _FakeTypeMutationGateway(name="sub_401000")
    use_case = SetTypeUseCase(gateway, _FakeDatabase())

    result = use_case.execute(
        SetTypeCommand(address="0x401000", type="int f(char *)")
    )

    assert isinstance(result, SetTypeResult)
    assert gateway.applies == [_Apply(Address(ea), "int f(char *)")]
    application = result.application
    assert isinstance(application, TypeApplication)
    assert application.address == Address(ea)
    assert application.name == "sub_401000"
    assert application.type == "int f(char *)"


def test_result_carries_the_name_reported_by_the_gateway():
    gateway = _FakeTypeMutationGateway(name="g_config")
    use_case = SetTypeUseCase(gateway, _FakeDatabase())

    result = use_case.execute(
        SetTypeCommand(address="0x404000", type="unsigned int")
    )

    # The name is whatever the retyped item carries afterward, not derived from
    # the declaration.
    assert result.application.name == "g_config"


def test_unnamed_item_yields_empty_name():
    gateway = _FakeTypeMutationGateway(name="")
    use_case = SetTypeUseCase(gateway, _FakeDatabase())

    result = use_case.execute(SetTypeCommand(address="0x500", type="char"))

    assert result.application.name == ""


def test_declaration_is_stripped_before_apply_and_in_result():
    ea = 0x402000
    gateway = _FakeTypeMutationGateway(name="fn")
    use_case = SetTypeUseCase(gateway, _FakeDatabase())

    result = use_case.execute(
        SetTypeCommand(address=hex(ea), type="  int f(char *)  ")
    )

    # The gateway sees the trimmed declaration, and the trimmed form is reported.
    assert gateway.applies == [_Apply(Address(ea), "int f(char *)")]
    assert result.application.type == "int f(char *)"


def test_resolves_decimal_and_symbol_addresses():
    sym_ea = 0x406060
    gateway = _FakeTypeMutationGateway(name="handler")
    database = _FakeDatabase(symbols={"handler": sym_ea})
    use_case = SetTypeUseCase(gateway, database)

    dec = use_case.execute(SetTypeCommand(address="4218880", type="int"))
    assert dec.application.address == Address(4218880)

    sym = use_case.execute(
        SetTypeCommand(address="handler", type="void (*)(int)")
    )
    assert sym.application.address == Address(sym_ea)
    assert gateway.applies[-1].ea == Address(sym_ea)


# -- use-case: declaration guard --------------------------------------------


@pytest.mark.parametrize("blank", ["", "   ", "\t", "\n  \n"])
def test_empty_or_blank_declaration_raises_before_touching_gateway(blank: str):
    gateway = _FakeTypeMutationGateway()
    use_case = SetTypeUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(SetTypeCommand(address="0x401000", type=blank))
    # The guard runs first: neither resolution nor an apply was attempted.
    assert gateway.applies == []


def test_non_string_declaration_raises():
    gateway = _FakeTypeMutationGateway()
    use_case = SetTypeUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(
            SetTypeCommand(address="0x401000", type=123)  # type: ignore[arg-type]
        )
    assert gateway.applies == []


# -- use-case: failure paths ------------------------------------------------


def test_unparseable_declaration_propagates():
    bad = "int (((("
    gateway = _FakeTypeMutationGateway(unparseable=frozenset({bad}))
    use_case = SetTypeUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(SetTypeCommand(address="0x401000", type=bad))


def test_type_that_cannot_be_applied_propagates():
    orphan = 0x600100
    gateway = _FakeTypeMutationGateway(unappliable=frozenset({orphan}))
    use_case = SetTypeUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(SetTypeCommand(address=hex(orphan), type="int"))


def test_unresolvable_symbol_raises_and_skips_apply():
    gateway = _FakeTypeMutationGateway()
    use_case = SetTypeUseCase(gateway, _FakeDatabase())

    with pytest.raises(ValueError):
        use_case.execute(SetTypeCommand(address="missing", type="int"))
    assert gateway.applies == []  # resolution fails before any apply


# -- view -------------------------------------------------------------------


def test_view_projects_application_to_flat_shape():
    application = TypeApplication(
        address=Address(0x401000), name="sub_401000", type="int f(char *)"
    )

    view = set_type_view(application)

    assert view == {
        "address": "0x401000",
        "name": "sub_401000",
        "type": "int f(char *)",
        "ok": True,
    }


def test_view_preserves_empty_name_and_reports_ok_true():
    application = TypeApplication(
        address=Address(0x402000), name="", type="unsigned int"
    )

    view = set_type_view(application)

    assert view["name"] == ""
    assert view["type"] == "unsigned int"
    assert view["ok"] is True
    assert view["address"] == "0x402000"


# -- catalog registration ---------------------------------------------------


def _register(gateway: _FakeTypeMutationGateway, database: _FakeDatabase, executor):
    registry = Registry()
    register_set_type(
        registry,
        set_type_use_case=SetTypeUseCase(gateway, database),
        executor=executor,
    )
    return registry


def test_tool_is_registered_as_mutating():
    registry = _register(_FakeTypeMutationGateway(), _FakeDatabase(), _InlineExecutor())

    spec = registry.get_tool("set_type")
    assert spec is not None
    assert spec.annotations["readOnlyHint"] is False
    # Applying a type replaces an annotation, not user data — not destructive.
    assert "destructiveHint" not in spec.annotations


def test_tool_invocation_applies_through_gateway_with_write_affinity():
    ea = 0x401000
    gateway = _FakeTypeMutationGateway(name="sub_401000")
    executor = _InlineExecutor()
    registry = _register(gateway, _FakeDatabase(), executor)

    invoke = registry.get_tool("set_type").invoke
    view = invoke(address="0x401000", type="  int f(char *)  ")

    assert view == {
        "address": "0x401000",
        "name": "sub_401000",
        "type": "int f(char *)",
        "ok": True,
    }
    # The stripped declaration reached the gateway at the resolved address.
    assert gateway.applies == [_Apply(Address(ea), "int f(char *)")]
    # The mutation was marshalled with explicit write affinity.
    assert executor.write_flags == [True]


def test_tool_invocation_surfaces_unparseable_type_as_toolerror():
    bad = "int (((("
    gateway = _FakeTypeMutationGateway(unparseable=frozenset({bad}))
    registry = _register(gateway, _FakeDatabase(), _InlineExecutor())

    invoke = registry.get_tool("set_type").invoke
    with pytest.raises(ToolError):
        invoke(address="0x401000", type=bad)


def test_tool_invocation_surfaces_empty_type_as_toolerror():
    registry = _register(_FakeTypeMutationGateway(), _FakeDatabase(), _InlineExecutor())

    invoke = registry.get_tool("set_type").invoke
    with pytest.raises(ToolError):
        invoke(address="0x401000", type="   ")


def test_tool_invocation_surfaces_unresolvable_address_as_toolerror():
    registry = _register(_FakeTypeMutationGateway(), _FakeDatabase(), _InlineExecutor())

    invoke = registry.get_tool("set_type").invoke
    with pytest.raises(ToolError):
        invoke(address="ghost", type="int")
