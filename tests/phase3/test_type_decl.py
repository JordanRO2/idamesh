"""Unit tests for the ``declare_type`` and ``enum_upsert`` mutation tools (no IDA).

Both tools take **no address**, so the fakes here stand in only for the write
gateways. A fake :class:`TypeDeclarationGateway` records every source it parses and
can refuse one (mirroring ``parse_decls`` returning a non-zero error count); a fake
:class:`EnumGateway` records every upsert, models a persistent enum so a second
call *extends* rather than replaces, and can refuse a member (mirroring an SDK
``set_enum_details`` / ``set_named_type`` failure). Exercising them through the
use-cases and the catalog registration checks the input guards, the derived
``count``, the non-destructive member merge, the wire projections, the mutating
annotations, the explicit write affinity, and the error surfacing — all without a
database.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Mapping, Tuple, TypeVar

import pytest

from idamesh.application.contexts.declare_type import DeclareTypeUseCase
from idamesh.application.contexts.enum_upsert import EnumUpsertUseCase
from idamesh.application.dto.declare_type import (
    DeclareTypeCommand,
    DeclareTypeResult,
)
from idamesh.application.dto.enum_upsert import (
    EnumUpsertCommand,
    EnumUpsertResult,
)
from idamesh.domain.entities.enum_definition import EnumDefinition
from idamesh.domain.entities.type_declaration import TypeDeclaration
from idamesh.interface.catalog.declare_type import (
    declare_type_view,
    register_declare_type,
)
from idamesh.interface.catalog.enum_upsert import (
    enum_upsert_view,
    register_enum_upsert,
)
from idamesh.interface.mcp.engine import ToolError
from idamesh.interface.mcp.registry import Registry

T = TypeVar("T")


# -- fakes ------------------------------------------------------------------


@dataclass
class _Declaration:
    """One recorded parse (the exact source text the gateway saw)."""

    source: str


class _FakeTypeDeclarationGateway:
    """An in-memory ``TypeDeclarationGateway`` that records parses and can refuse.

    ``names`` is the tuple returned on success (the types the source installed). A
    source listed in ``unparseable`` raises as the real adapter does when
    ``parse_decls`` reports a non-zero error count. Every call is recorded first so
    a test can assert the *stripped* source reached the SDK.
    """

    def __init__(
        self,
        *,
        names: Tuple[str, ...] = (),
        unparseable: frozenset[str] = frozenset(),
    ) -> None:
        self._names = names
        self._unparseable = unparseable
        self.parses: List[_Declaration] = []

    def declare_types(self, declaration: str) -> Tuple[str, ...]:
        self.parses.append(_Declaration(source=declaration))
        if declaration in self._unparseable:
            raise ValueError(
                f"cannot parse type declaration (1 error(s)): {declaration!r}"
            )
        return self._names


@dataclass
class _Upsert:
    """One recorded upsert (the enum name and the members map the gateway saw)."""

    name: str
    members: Dict[str, int]


class _FakeEnumGateway:
    """An in-memory ``EnumGateway`` modelling a persistent, non-destructive enum.

    Each named enum keeps a live ``{member: value}`` map across calls, so a second
    upsert *extends* the first: listed members are added or updated and unlisted
    members are preserved, exactly as the real create-or-extend adapter does. A
    member name in ``refuse`` raises as the SDK does when a member cannot be
    installed. ``created`` records the names for which a fresh enum was minted, so a
    test can assert create-vs-update. Every call is recorded first.
    """

    def __init__(self, *, refuse: frozenset[str] = frozenset()) -> None:
        self._refuse = refuse
        self._enums: Dict[str, Dict[str, int]] = {}
        self.created: List[str] = []
        self.upserts: List[_Upsert] = []

    def upsert(self, name: str, members: Mapping[str, int]) -> int:
        self.upserts.append(_Upsert(name=name, members=dict(members)))
        current = self._enums.get(name)
        if current is None:
            current = {}
            self._enums[name] = current
            self.created.append(name)
        for member_name, value in members.items():
            if member_name in self._refuse:
                raise ValueError(f"cannot add enum member {member_name!r}")
            current[member_name] = value
        return len(current)


class _InlineExecutor:
    """A ``MainThreadExecutor`` that runs jobs inline, recording write affinity."""

    def __init__(self) -> None:
        self.write_flags: List[bool] = []

    def run(self, job: Callable[[], T], *, write: bool = True) -> T:
        self.write_flags.append(write)
        return job()

    def on_kernel_thread(self) -> bool:
        return True


# == declare_type ===========================================================

# -- use-case: parse & report ----------------------------------------------


def test_declare_forwards_source_and_reports_names_and_count():
    gateway = _FakeTypeDeclarationGateway(names=("Point", "Rect"))
    use_case = DeclareTypeUseCase(gateway)

    result = use_case.execute(
        DeclareTypeCommand(declaration="struct Point { int x; }; struct Rect {};")
    )

    assert isinstance(result, DeclareTypeResult)
    declaration = result.declaration
    assert isinstance(declaration, TypeDeclaration)
    assert declaration.names == ("Point", "Rect")
    # ``count`` is derived from the names, never sent separately.
    assert declaration.count == 2


def test_declare_source_is_stripped_before_parse():
    gateway = _FakeTypeDeclarationGateway(names=("Widget",))
    use_case = DeclareTypeUseCase(gateway)

    use_case.execute(
        DeclareTypeCommand(declaration="  \n typedef int Widget;  \t ")
    )

    # The gateway sees the trimmed source, not the padded input.
    assert gateway.parses == [_Declaration("typedef int Widget;")]


def test_declare_valid_source_that_adds_no_named_type_reports_zero():
    gateway = _FakeTypeDeclarationGateway(names=())
    use_case = DeclareTypeUseCase(gateway)

    result = use_case.execute(DeclareTypeCommand(declaration="int;"))

    assert result.declaration.names == ()
    assert result.declaration.count == 0


# -- use-case: source guard -------------------------------------------------


@pytest.mark.parametrize("blank", ["", "   ", "\t", "\n  \n"])
def test_empty_or_blank_declaration_raises_before_touching_gateway(blank: str):
    gateway = _FakeTypeDeclarationGateway(names=("X",))
    use_case = DeclareTypeUseCase(gateway)

    with pytest.raises(ValueError):
        use_case.execute(DeclareTypeCommand(declaration=blank))
    assert gateway.parses == []


def test_non_string_declaration_raises():
    gateway = _FakeTypeDeclarationGateway()
    use_case = DeclareTypeUseCase(gateway)

    with pytest.raises(ValueError):
        use_case.execute(
            DeclareTypeCommand(declaration=123)  # type: ignore[arg-type]
        )
    assert gateway.parses == []


# -- use-case: failure path -------------------------------------------------


def test_unparseable_source_propagates():
    bad = "struct { {{"
    gateway = _FakeTypeDeclarationGateway(unparseable=frozenset({bad}))
    use_case = DeclareTypeUseCase(gateway)

    with pytest.raises(ValueError):
        use_case.execute(DeclareTypeCommand(declaration=bad))


# -- view -------------------------------------------------------------------


def test_declare_view_projects_to_flat_shape():
    declaration = TypeDeclaration(names=("Point", "Rect"))

    view = declare_type_view(declaration)

    assert view == {"ok": True, "count": 2, "names": ["Point", "Rect"]}


def test_declare_view_reports_zero_for_no_names():
    view = declare_type_view(TypeDeclaration(names=()))

    assert view == {"ok": True, "count": 0, "names": []}


# -- catalog registration ---------------------------------------------------


def _register_declare(gateway: _FakeTypeDeclarationGateway, executor) -> Registry:
    registry = Registry()
    register_declare_type(
        registry,
        declare_type_use_case=DeclareTypeUseCase(gateway),
        executor=executor,
    )
    return registry


def test_declare_tool_is_registered_as_mutating_not_destructive():
    registry = _register_declare(_FakeTypeDeclarationGateway(), _InlineExecutor())

    spec = registry.get_tool("declare_type")
    assert spec is not None
    assert spec.annotations["readOnlyHint"] is False
    # Adding a type installs a definition; it never deletes user data.
    assert "destructiveHint" not in spec.annotations


def test_declare_tool_invocation_parses_with_write_affinity():
    gateway = _FakeTypeDeclarationGateway(names=("Point",))
    executor = _InlineExecutor()
    registry = _register_declare(gateway, executor)

    invoke = registry.get_tool("declare_type").invoke
    view = invoke(declaration="  struct Point { int x; };  ")

    assert view == {"ok": True, "count": 1, "names": ["Point"]}
    assert gateway.parses == [_Declaration("struct Point { int x; };")]
    assert executor.write_flags == [True]


def test_declare_tool_invocation_surfaces_unparseable_as_toolerror():
    bad = "struct { {{"
    gateway = _FakeTypeDeclarationGateway(unparseable=frozenset({bad}))
    registry = _register_declare(gateway, _InlineExecutor())

    invoke = registry.get_tool("declare_type").invoke
    with pytest.raises(ToolError):
        invoke(declaration=bad)


def test_declare_tool_invocation_surfaces_empty_source_as_toolerror():
    registry = _register_declare(_FakeTypeDeclarationGateway(), _InlineExecutor())

    invoke = registry.get_tool("declare_type").invoke
    with pytest.raises(ToolError):
        invoke(declaration="   ")


# == enum_upsert ============================================================

# -- use-case: create vs update --------------------------------------------


def test_upsert_creates_enum_and_reports_member_count():
    gateway = _FakeEnumGateway()
    use_case = EnumUpsertUseCase(gateway)

    result = use_case.execute(
        EnumUpsertCommand(name="Color", members={"RED": 0, "GREEN": 1})
    )

    assert isinstance(result, EnumUpsertResult)
    definition = result.definition
    assert isinstance(definition, EnumDefinition)
    assert definition.name == "Color"
    assert definition.member_count == 2
    assert gateway.created == ["Color"]
    assert gateway.upserts == [_Upsert("Color", {"RED": 0, "GREEN": 1})]


def test_upsert_extends_existing_enum_without_clobbering_unlisted_members():
    gateway = _FakeEnumGateway()
    use_case = EnumUpsertUseCase(gateway)

    use_case.execute(EnumUpsertCommand(name="Color", members={"RED": 0}))
    # A second upsert adds a new member and updates none of the first.
    result = use_case.execute(
        EnumUpsertCommand(name="Color", members={"GREEN": 1, "BLUE": 2})
    )

    # The enum was created once and extended once, not recreated.
    assert gateway.created == ["Color"]
    # The unlisted RED survived: total is the union of both calls.
    assert result.definition.member_count == 3


def test_upsert_updates_a_members_value_in_place():
    gateway = _FakeEnumGateway()
    use_case = EnumUpsertUseCase(gateway)

    use_case.execute(EnumUpsertCommand(name="Flags", members={"A": 1}))
    result = use_case.execute(EnumUpsertCommand(name="Flags", members={"A": 7}))

    # Updating an existing member changes its value but not the count.
    assert result.definition.member_count == 1
    assert gateway._enums["Flags"]["A"] == 7


def test_upsert_strips_member_names_before_the_gateway():
    gateway = _FakeEnumGateway()
    use_case = EnumUpsertUseCase(gateway)

    use_case.execute(
        EnumUpsertCommand(name="  Color  ", members={"  RED  ": 0})
    )

    # The name and member key reach the gateway trimmed.
    assert gateway.upserts == [_Upsert("Color", {"RED": 0})]


# -- use-case: input guards -------------------------------------------------


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_empty_or_blank_enum_name_raises_before_gateway(blank: str):
    gateway = _FakeEnumGateway()
    use_case = EnumUpsertUseCase(gateway)

    with pytest.raises(ValueError):
        use_case.execute(EnumUpsertCommand(name=blank, members={"A": 0}))
    assert gateway.upserts == []


def test_non_string_enum_name_raises():
    gateway = _FakeEnumGateway()
    use_case = EnumUpsertUseCase(gateway)

    with pytest.raises(ValueError):
        use_case.execute(
            EnumUpsertCommand(name=42, members={"A": 0})  # type: ignore[arg-type]
        )
    assert gateway.upserts == []


def test_empty_member_map_raises_before_gateway():
    gateway = _FakeEnumGateway()
    use_case = EnumUpsertUseCase(gateway)

    with pytest.raises(ValueError):
        use_case.execute(EnumUpsertCommand(name="Color", members={}))
    assert gateway.upserts == []


def test_non_mapping_members_raises():
    gateway = _FakeEnumGateway()
    use_case = EnumUpsertUseCase(gateway)

    with pytest.raises(ValueError):
        use_case.execute(
            EnumUpsertCommand(name="Color", members=[("RED", 0)])  # type: ignore[arg-type]
        )
    assert gateway.upserts == []


def test_blank_member_name_raises():
    gateway = _FakeEnumGateway()
    use_case = EnumUpsertUseCase(gateway)

    with pytest.raises(ValueError):
        use_case.execute(EnumUpsertCommand(name="Color", members={"  ": 0}))
    assert gateway.upserts == []


def test_boolean_member_value_is_rejected():
    gateway = _FakeEnumGateway()
    use_case = EnumUpsertUseCase(gateway)

    # ``bool`` is an ``int`` subclass; the guard must reject it explicitly.
    with pytest.raises(ValueError):
        use_case.execute(
            EnumUpsertCommand(name="Color", members={"RED": True})  # type: ignore[dict-item]
        )
    assert gateway.upserts == []


def test_non_integer_member_value_is_rejected():
    gateway = _FakeEnumGateway()
    use_case = EnumUpsertUseCase(gateway)

    with pytest.raises(ValueError):
        use_case.execute(
            EnumUpsertCommand(name="Color", members={"RED": "zero"})  # type: ignore[dict-item]
        )
    assert gateway.upserts == []


# -- use-case: failure path -------------------------------------------------


def test_refused_member_propagates():
    gateway = _FakeEnumGateway(refuse=frozenset({"BAD"}))
    use_case = EnumUpsertUseCase(gateway)

    with pytest.raises(ValueError):
        use_case.execute(EnumUpsertCommand(name="Color", members={"BAD": 9}))


# -- view -------------------------------------------------------------------


def test_enum_view_projects_to_flat_shape():
    definition = EnumDefinition(name="Color", member_count=3)

    view = enum_upsert_view(definition)

    assert view == {"name": "Color", "ok": True, "member_count": 3}


# -- catalog registration ---------------------------------------------------


def _register_enum(gateway: _FakeEnumGateway, executor) -> Registry:
    registry = Registry()
    register_enum_upsert(
        registry,
        enum_upsert_use_case=EnumUpsertUseCase(gateway),
        executor=executor,
    )
    return registry


def test_enum_tool_is_registered_as_mutating_not_destructive():
    registry = _register_enum(_FakeEnumGateway(), _InlineExecutor())

    spec = registry.get_tool("enum_upsert")
    assert spec is not None
    assert spec.annotations["readOnlyHint"] is False
    # An upsert extends an enum; it never removes members -> not destructive.
    assert "destructiveHint" not in spec.annotations


def test_enum_tool_invocation_upserts_with_write_affinity():
    gateway = _FakeEnumGateway()
    executor = _InlineExecutor()
    registry = _register_enum(gateway, executor)

    invoke = registry.get_tool("enum_upsert").invoke
    view = invoke(name="Color", members={"RED": 0, "GREEN": 1})

    assert view == {"name": "Color", "ok": True, "member_count": 2}
    assert gateway.upserts == [_Upsert("Color", {"RED": 0, "GREEN": 1})]
    assert executor.write_flags == [True]


def test_enum_tool_invocation_surfaces_empty_members_as_toolerror():
    registry = _register_enum(_FakeEnumGateway(), _InlineExecutor())

    invoke = registry.get_tool("enum_upsert").invoke
    with pytest.raises(ToolError):
        invoke(name="Color", members={})


def test_enum_tool_invocation_surfaces_refused_member_as_toolerror():
    gateway = _FakeEnumGateway(refuse=frozenset({"BAD"}))
    registry = _register_enum(gateway, _InlineExecutor())

    invoke = registry.get_tool("enum_upsert").invoke
    with pytest.raises(ToolError):
        invoke(name="Color", members={"BAD": 9})
