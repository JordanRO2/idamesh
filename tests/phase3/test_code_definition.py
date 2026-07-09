"""Unit tests for the ``define_func`` and ``undefine`` mutation tools (no IDA).

Fake :class:`CodeDefinitionGateway` and :class:`DatabaseGateway` implementations
stand in for the IDA adapters, so the whole write path is exercised off-host: each
use-case resolves a polymorphic selector, routes the create/undefine through the
shared code-definition gateway, and wraps the outcome; the ``DefineFuncView`` /
``UndefineView`` project the completed change; and the registered tools marshal
through the executor, advertise ``readOnlyHint: false`` (and, for ``undefine``,
``destructiveHint: true``), and turn a refused create/undefine into an ``isError``
(``ToolError``) instead of a crash.
"""

from __future__ import annotations

import pytest

from idamesh.application.contexts.define_func import (
    DefineFuncUseCase,
    UndefineUseCase,
)
from idamesh.application.dto.define_func import (
    DefineFuncCommand,
    UndefineCommand,
)
from idamesh.domain.entities.code_definition import (
    FunctionDefinition,
    Undefinition,
)
from idamesh.domain.values.address import Address, Selector
from idamesh.infrastructure.execution.inline import InlineExecutor
from idamesh.interface.catalog.define_func import (
    define_func_view,
    register_define_func,
)
from idamesh.interface.catalog.undefine import register_undefine, undefine_view
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


class _FakeCodeDefinitionGateway:
    """In-memory code-definition gateway: records writes, models refusals.

    ``names`` maps an EA to the name a successful :meth:`define_func` reports (an
    absent entry means the created function is unnamed → ``None``). ``refuse_define``
    and ``refuse_undefine`` are the sets of EAs the analyzer/database refuses, so a
    write there raises — mirroring the adapter surfacing a falsey SDK return as a
    domain error rather than a silent no-op.
    """

    def __init__(
        self,
        names: dict[int, str] | None = None,
        refuse_define: set[int] | None = None,
        refuse_undefine: set[int] | None = None,
    ) -> None:
        self._names = dict(names or {})
        self._refuse_define = set(refuse_define or set())
        self._refuse_undefine = set(refuse_undefine or set())
        self.defined: list[int] = []
        self.undefined: list[int] = []

    def define_func(self, ea: Address):
        if int(ea) in self._refuse_define:
            raise ValueError(
                f"cannot create a function at {ea.hex()}: nothing to base one on"
            )
        self.defined.append(int(ea))
        return self._names.get(int(ea))

    def undefine(self, ea: Address) -> None:
        if int(ea) in self._refuse_undefine:
            raise ValueError(f"nothing to undefine at {ea.hex()}")
        self.undefined.append(int(ea))


# --------------------------------------------------------------------------- #
# define_func use-case: happy path
# --------------------------------------------------------------------------- #


def test_define_use_case_creates_function_and_reports_name():
    code = _FakeCodeDefinitionGateway(names={0x401000: "sub_401000"})
    use_case = DefineFuncUseCase(code, _FakeDatabaseGateway())

    result = use_case.execute(DefineFuncCommand(address="0x401000"))

    definition = result.definition
    assert isinstance(definition, FunctionDefinition)
    assert definition.address == Address(0x401000)
    assert definition.name == "sub_401000"
    # The gateway saw exactly one create, at the resolved EA.
    assert code.defined == [0x401000]


def test_define_use_case_reports_none_name_for_unnamed_function():
    code = _FakeCodeDefinitionGateway()
    use_case = DefineFuncUseCase(code, _FakeDatabaseGateway())

    result = use_case.execute(DefineFuncCommand(address="0x401000"))

    # A newly created function with no name reports ``None``.
    assert result.definition.name is None
    assert code.defined == [0x401000]


def test_define_use_case_resolves_symbol_selector_before_writing():
    code = _FakeCodeDefinitionGateway(names={0x401000: "sub_401000"})
    database = _FakeDatabaseGateway(symbols={"entry": 0x401000})
    use_case = DefineFuncUseCase(code, database)

    result = use_case.execute(DefineFuncCommand(address="entry"))

    # The symbol name was resolved to its EA, and the create targeted that EA.
    assert code.defined == [0x401000]
    assert result.definition.address == Address(0x401000)


def test_define_use_case_resolves_decimal_selector():
    code = _FakeCodeDefinitionGateway()
    use_case = DefineFuncUseCase(code, _FakeDatabaseGateway())

    use_case.execute(DefineFuncCommand(address="4198400"))  # 0x401000

    assert code.defined == [0x401000]


# --------------------------------------------------------------------------- #
# define_func use-case: rejected inputs (become isError at the boundary)
# --------------------------------------------------------------------------- #


def test_define_use_case_propagates_refused_creation():
    code = _FakeCodeDefinitionGateway(refuse_define={0x401000})
    use_case = DefineFuncUseCase(code, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(DefineFuncCommand(address="0x401000"))

    # The refusal happened at the gateway; nothing was recorded as created.
    assert code.defined == []


def test_define_use_case_propagates_unresolvable_symbol():
    code = _FakeCodeDefinitionGateway()
    # No symbol table entry — resolution fails before any write.
    use_case = DefineFuncUseCase(code, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(DefineFuncCommand(address="nonexistent_symbol"))

    assert code.defined == []


# --------------------------------------------------------------------------- #
# undefine use-case: happy path
# --------------------------------------------------------------------------- #


def test_undefine_use_case_reverts_item_at_resolved_address():
    code = _FakeCodeDefinitionGateway()
    use_case = UndefineUseCase(code, _FakeDatabaseGateway())

    result = use_case.execute(UndefineCommand(address="0x401000"))

    undefinition = result.undefinition
    assert isinstance(undefinition, Undefinition)
    assert undefinition.address == Address(0x401000)
    assert code.undefined == [0x401000]


def test_undefine_use_case_resolves_symbol_selector_before_writing():
    code = _FakeCodeDefinitionGateway()
    database = _FakeDatabaseGateway(symbols={"sub_401000": 0x401000})
    use_case = UndefineUseCase(code, database)

    result = use_case.execute(UndefineCommand(address="sub_401000"))

    assert code.undefined == [0x401000]
    assert result.undefinition.address == Address(0x401000)


# --------------------------------------------------------------------------- #
# undefine use-case: rejected inputs (become isError at the boundary)
# --------------------------------------------------------------------------- #


def test_undefine_use_case_propagates_nothing_to_undefine():
    code = _FakeCodeDefinitionGateway(refuse_undefine={0x401000})
    use_case = UndefineUseCase(code, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(UndefineCommand(address="0x401000"))

    assert code.undefined == []


def test_undefine_use_case_propagates_unresolvable_symbol():
    code = _FakeCodeDefinitionGateway()
    use_case = UndefineUseCase(code, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(UndefineCommand(address="nonexistent_symbol"))

    assert code.undefined == []


# --------------------------------------------------------------------------- #
# View projections
# --------------------------------------------------------------------------- #


def test_define_view_projects_definition_to_wire_shape():
    view = define_func_view(
        FunctionDefinition(address=Address(0x401000), name="sub_401000")
    )

    assert view == {
        "address": "0x401000",
        "ok": True,
        "name": "sub_401000",
    }


def test_define_view_carries_null_name_through():
    view = define_func_view(
        FunctionDefinition(address=Address(0x14000A), name=None)
    )

    assert view["name"] is None
    assert view["address"] == "0x14000a"
    assert view["ok"] is True


def test_undefine_view_projects_undefinition_to_wire_shape():
    view = undefine_view(Undefinition(address=Address(0x401000)))

    assert view == {
        "address": "0x401000",
        "ok": True,
    }


# --------------------------------------------------------------------------- #
# Registered tools: annotations, invocation, and isError translation
# --------------------------------------------------------------------------- #


def _register_define(use_case: DefineFuncUseCase) -> Registry:
    registry = Registry()
    register_define_func(
        registry, define_func_use_case=use_case, executor=InlineExecutor()
    )
    return registry


def _register_undefine(use_case: UndefineUseCase) -> Registry:
    registry = Registry()
    register_undefine(
        registry, undefine_use_case=use_case, executor=InlineExecutor()
    )
    return registry


def test_define_tool_is_advertised_as_mutating():
    registry = _register_define(
        DefineFuncUseCase(_FakeCodeDefinitionGateway(), _FakeDatabaseGateway())
    )

    spec = registry.get_tool("define_func")
    assert spec is not None
    # ``@registry.mutating`` flips the default read-only advertisement off.
    assert spec.annotations["readOnlyHint"] is False
    # A plain create is not flagged destructive.
    assert "destructiveHint" not in spec.annotations


def test_undefine_tool_is_advertised_as_destructive():
    registry = _register_undefine(
        UndefineUseCase(_FakeCodeDefinitionGateway(), _FakeDatabaseGateway())
    )

    spec = registry.get_tool("undefine")
    assert spec is not None
    # ``@registry.destructive`` sets both hints.
    assert spec.annotations["readOnlyHint"] is False
    assert spec.annotations["destructiveHint"] is True


def test_define_tool_invocation_returns_view_with_name():
    code = _FakeCodeDefinitionGateway(names={0x401000: "sub_401000"})
    spec = _register_define(
        DefineFuncUseCase(code, _FakeDatabaseGateway())
    ).get_tool("define_func")

    result = spec.invoke(address="0x401000")

    assert result == {
        "address": "0x401000",
        "ok": True,
        "name": "sub_401000",
    }


def test_undefine_tool_invocation_returns_view():
    code = _FakeCodeDefinitionGateway()
    spec = _register_undefine(
        UndefineUseCase(code, _FakeDatabaseGateway())
    ).get_tool("undefine")

    result = spec.invoke(address="0x401000")

    assert result == {
        "address": "0x401000",
        "ok": True,
    }
    assert code.undefined == [0x401000]


def test_define_tool_invocation_surfaces_refusal_as_tool_error():
    code = _FakeCodeDefinitionGateway(refuse_define={0x401000})
    spec = _register_define(
        DefineFuncUseCase(code, _FakeDatabaseGateway())
    ).get_tool("define_func")

    # A refused create is a per-call failure (isError), not a protocol fault.
    with pytest.raises(ToolError):
        spec.invoke(address="0x401000")


def test_define_tool_invocation_surfaces_unresolvable_address_as_tool_error():
    spec = _register_define(
        DefineFuncUseCase(_FakeCodeDefinitionGateway(), _FakeDatabaseGateway())
    ).get_tool("define_func")

    with pytest.raises(ToolError):
        spec.invoke(address="nonexistent_symbol")


def test_undefine_tool_invocation_surfaces_refusal_as_tool_error():
    code = _FakeCodeDefinitionGateway(refuse_undefine={0x401000})
    spec = _register_undefine(
        UndefineUseCase(code, _FakeDatabaseGateway())
    ).get_tool("undefine")

    with pytest.raises(ToolError):
        spec.invoke(address="0x401000")


def test_undefine_tool_invocation_surfaces_unresolvable_address_as_tool_error():
    spec = _register_undefine(
        UndefineUseCase(_FakeCodeDefinitionGateway(), _FakeDatabaseGateway())
    ).get_tool("undefine")

    with pytest.raises(ToolError):
        spec.invoke(address="nonexistent_symbol")
