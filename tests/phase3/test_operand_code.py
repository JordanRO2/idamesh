"""Unit tests for the ``set_op_type`` and ``define_code`` mutation tools (no IDA).

Fake :class:`OperandGateway`, :class:`InstructionGateway` and
:class:`DatabaseGateway` implementations stand in for the IDA adapters, so the
whole write path is exercised off-host: each use-case validates its input,
resolves a polymorphic selector, routes the change through its gateway, and wraps
the outcome; the ``SetOpTypeView`` / ``DefineCodeView`` project the completed
change; and the registered tools marshal through the executor, advertise
``readOnlyHint: false`` (neither is destructive), and turn a refused write into an
``isError`` (``ToolError``) instead of a crash.

The operand *vocabulary* — which display kinds are accepted, the ``chr`` → ``char``
canonicalisation, and the rejection of an unknown kind — is additionally checked
directly against the real :class:`IdaOperandGateway`, whose kind classification
runs *before* any lazy ``ida_*`` import and so is reachable with no IDA installed.
"""

from __future__ import annotations

import pytest

from idamesh.application.contexts.define_code import DefineCodeUseCase
from idamesh.application.contexts.set_op_type import SetOpTypeUseCase
from idamesh.application.dto.define_code import DefineCodeCommand
from idamesh.application.dto.set_op_type import SetOpTypeCommand
from idamesh.domain.entities.instruction_definition import InstructionDefinition
from idamesh.domain.entities.operand_type import OperandTypeSetting
from idamesh.domain.values.address import Address, Selector
from idamesh.infrastructure.execution.inline import InlineExecutor
from idamesh.infrastructure.ida.operand_adapter import (
    _NUMERIC_KINDS,
    IdaOperandGateway,
)
from idamesh.interface.catalog.define_code import (
    define_code_view,
    register_define_code,
)
from idamesh.interface.catalog.set_op_type import (
    register_set_op_type,
    set_op_type_view,
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


class _FakeOperandGateway:
    """In-memory operand gateway: records writes, canonicalises, models refusals.

    ``_CANON`` mirrors the real adapter's vocabulary and its ``chr`` → ``char``
    canonicalisation. ``refuse`` is a set of ``(ea, operand)`` pairs the database
    refuses, so a write there raises — mirroring the adapter surfacing a falsey SDK
    return as a domain error rather than a silent no-op. An unknown kind raises,
    matching the adapter's pre-SDK classification guard.
    """

    _CANON = {
        "hex": "hex",
        "dec": "dec",
        "oct": "oct",
        "bin": "bin",
        "char": "char",
        "chr": "char",
        "offset": "offset",
    }

    def __init__(self, refuse: set[tuple[int, int]] | None = None) -> None:
        self._refuse = set(refuse or set())
        self.calls: list[tuple[int, int, str]] = []

    def set_op_type(self, ea: Address, operand: int, kind: str) -> str:
        label = kind.strip().lower()
        if label not in self._CANON:
            raise ValueError(f"unknown operand type {kind!r}")
        if (int(ea), operand) in self._refuse:
            raise ValueError(
                f"cannot set operand {operand} at {ea.hex()} to {label!r}"
            )
        canon = self._CANON[label]
        self.calls.append((int(ea), operand, canon))
        return canon


class _FakeInstructionGateway:
    """In-memory instruction gateway: records creates, reports sizes, refuses.

    ``sizes`` maps an EA to the byte length a successful :meth:`define_code`
    reports (an absent entry defaults to 1). ``refuse`` is the set of EAs whose
    bytes do not decode, so a create there raises — mirroring the adapter surfacing
    a zero ``create_insn`` return as a domain error.
    """

    def __init__(
        self,
        sizes: dict[int, int] | None = None,
        refuse: set[int] | None = None,
    ) -> None:
        self._sizes = dict(sizes or {})
        self._refuse = set(refuse or set())
        self.defined: list[int] = []

    def define_code(self, ea: Address) -> int:
        if int(ea) in self._refuse:
            raise ValueError(
                f"cannot create an instruction at {ea.hex()}: the bytes there do "
                "not decode"
            )
        self.defined.append(int(ea))
        return self._sizes.get(int(ea), 1)


# --------------------------------------------------------------------------- #
# set_op_type use-case: happy path
# --------------------------------------------------------------------------- #


def test_set_op_type_use_case_applies_and_echoes_label():
    operands = _FakeOperandGateway()
    use_case = SetOpTypeUseCase(operands, _FakeDatabaseGateway())

    result = use_case.execute(
        SetOpTypeCommand(address="0x401000", operand=1, type="hex")
    )

    setting = result.setting
    assert isinstance(setting, OperandTypeSetting)
    assert setting.address == Address(0x401000)
    assert setting.operand == 1
    assert setting.type == "hex"
    # The gateway saw exactly one tag, at the resolved EA and operand.
    assert operands.calls == [(0x401000, 1, "hex")]


def test_set_op_type_use_case_reports_canonical_label_not_requested_kind():
    # The result carries the representation the gateway put in force, which may
    # differ from the requested spelling (``chr`` canonicalises to ``char``).
    operands = _FakeOperandGateway()
    use_case = SetOpTypeUseCase(operands, _FakeDatabaseGateway())

    result = use_case.execute(
        SetOpTypeCommand(address="0x401000", operand=0, type="chr")
    )

    assert result.setting.type == "char"
    assert operands.calls == [(0x401000, 0, "char")]


def test_set_op_type_use_case_strips_and_lowercases_kind():
    operands = _FakeOperandGateway()
    use_case = SetOpTypeUseCase(operands, _FakeDatabaseGateway())

    result = use_case.execute(
        SetOpTypeCommand(address="0x401000", operand=0, type="  HEX  ")
    )

    assert result.setting.type == "hex"


def test_set_op_type_use_case_resolves_symbol_selector_before_writing():
    operands = _FakeOperandGateway()
    database = _FakeDatabaseGateway(symbols={"main": 0x401000})
    use_case = SetOpTypeUseCase(operands, database)

    result = use_case.execute(
        SetOpTypeCommand(address="main", operand=0, type="dec")
    )

    assert operands.calls == [(0x401000, 0, "dec")]
    assert result.setting.address == Address(0x401000)


def test_set_op_type_use_case_resolves_decimal_selector():
    operands = _FakeOperandGateway()
    use_case = SetOpTypeUseCase(operands, _FakeDatabaseGateway())

    use_case.execute(SetOpTypeCommand(address="4198400", operand=0, type="bin"))

    assert operands.calls == [(0x401000, 0, "bin")]


# --------------------------------------------------------------------------- #
# set_op_type use-case: rejected inputs (become isError at the boundary)
# --------------------------------------------------------------------------- #


def test_set_op_type_use_case_rejects_negative_operand_before_resolving():
    operands = _FakeOperandGateway()
    use_case = SetOpTypeUseCase(operands, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(
            SetOpTypeCommand(address="0x401000", operand=-1, type="hex")
        )

    # Validation happens before any write.
    assert operands.calls == []


def test_set_op_type_use_case_rejects_boolean_operand():
    # ``bool`` is an ``int`` subclass; the guard rejects it explicitly so a
    # ``True`` operand cannot masquerade as operand ``1``.
    operands = _FakeOperandGateway()
    use_case = SetOpTypeUseCase(operands, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(
            SetOpTypeCommand(address="0x401000", operand=True, type="hex")
        )

    assert operands.calls == []


def test_set_op_type_use_case_rejects_blank_kind():
    operands = _FakeOperandGateway()
    use_case = SetOpTypeUseCase(operands, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(
            SetOpTypeCommand(address="0x401000", operand=0, type="   ")
        )

    assert operands.calls == []


def test_set_op_type_use_case_propagates_gateway_refusal():
    operands = _FakeOperandGateway(refuse={(0x401000, 2)})
    use_case = SetOpTypeUseCase(operands, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(
            SetOpTypeCommand(address="0x401000", operand=2, type="hex")
        )

    assert operands.calls == []


def test_set_op_type_use_case_propagates_unknown_kind_from_gateway():
    operands = _FakeOperandGateway()
    use_case = SetOpTypeUseCase(operands, _FakeDatabaseGateway())

    # A non-empty but unrecognised kind passes the application guard and is
    # rejected by the gateway (as the real adapter rejects it pre-SDK).
    with pytest.raises(ValueError):
        use_case.execute(
            SetOpTypeCommand(address="0x401000", operand=0, type="bogus")
        )

    assert operands.calls == []


def test_set_op_type_use_case_propagates_unresolvable_symbol():
    operands = _FakeOperandGateway()
    use_case = SetOpTypeUseCase(operands, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(
            SetOpTypeCommand(address="nonexistent_symbol", operand=0, type="hex")
        )

    assert operands.calls == []


# --------------------------------------------------------------------------- #
# define_code use-case: happy path
# --------------------------------------------------------------------------- #


def test_define_code_use_case_creates_instruction_and_reports_size():
    instructions = _FakeInstructionGateway(sizes={0x401000: 4})
    use_case = DefineCodeUseCase(instructions, _FakeDatabaseGateway())

    result = use_case.execute(DefineCodeCommand(address="0x401000"))

    definition = result.definition
    assert isinstance(definition, InstructionDefinition)
    assert definition.address == Address(0x401000)
    assert definition.size == 4
    assert instructions.defined == [0x401000]


def test_define_code_use_case_resolves_symbol_selector_before_writing():
    instructions = _FakeInstructionGateway(sizes={0x401000: 2})
    database = _FakeDatabaseGateway(symbols={"entry": 0x401000})
    use_case = DefineCodeUseCase(instructions, database)

    result = use_case.execute(DefineCodeCommand(address="entry"))

    assert instructions.defined == [0x401000]
    assert result.definition.address == Address(0x401000)
    assert result.definition.size == 2


def test_define_code_use_case_resolves_decimal_selector():
    instructions = _FakeInstructionGateway()
    use_case = DefineCodeUseCase(instructions, _FakeDatabaseGateway())

    use_case.execute(DefineCodeCommand(address="4198400"))  # 0x401000

    assert instructions.defined == [0x401000]


# --------------------------------------------------------------------------- #
# define_code use-case: rejected inputs (become isError at the boundary)
# --------------------------------------------------------------------------- #


def test_define_code_use_case_propagates_undecodable_bytes():
    instructions = _FakeInstructionGateway(refuse={0x401000})
    use_case = DefineCodeUseCase(instructions, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(DefineCodeCommand(address="0x401000"))

    # The refusal happened at the gateway; nothing was recorded as created.
    assert instructions.defined == []


def test_define_code_use_case_propagates_unresolvable_symbol():
    instructions = _FakeInstructionGateway()
    use_case = DefineCodeUseCase(instructions, _FakeDatabaseGateway())

    with pytest.raises(ValueError):
        use_case.execute(DefineCodeCommand(address="nonexistent_symbol"))

    assert instructions.defined == []


# --------------------------------------------------------------------------- #
# Real IdaOperandGateway: kind vocabulary + unknown-kind rejection (no IDA)
# --------------------------------------------------------------------------- #


def test_operand_adapter_rejects_unknown_kind_without_ida():
    # The kind classification runs before any lazy ``ida_*`` import, so an
    # unknown kind is a clean domain error even with no IDA installed. The
    # message names the accepted vocabulary.
    gateway = IdaOperandGateway()

    with pytest.raises(ValueError) as excinfo:
        gateway.set_op_type(Address(0x401000), 0, "definitely_not_a_kind")

    message = str(excinfo.value)
    assert "unknown operand type" in message
    for kind in ("hex", "dec", "oct", "bin", "char", "offset"):
        assert kind in message


def test_operand_adapter_numeric_kind_table_covers_the_bases():
    # The reproduced vocabulary maps every accepted numeric spelling to a
    # ``ida_bytes`` op-* primitive, with ``chr`` aliasing ``char``.
    assert set(_NUMERIC_KINDS) == {"hex", "dec", "oct", "bin", "char", "chr"}
    assert _NUMERIC_KINDS["char"] == "op_chr"
    assert _NUMERIC_KINDS["chr"] == "op_chr"
    assert _NUMERIC_KINDS["hex"] == "op_hex"


# --------------------------------------------------------------------------- #
# View projections
# --------------------------------------------------------------------------- #


def test_set_op_type_view_projects_setting_to_wire_shape():
    view = set_op_type_view(
        OperandTypeSetting(address=Address(0x401000), operand=1, type="hex")
    )

    assert view == {
        "address": "0x401000",
        "operand": 1,
        "type": "hex",
        "ok": True,
    }


def test_define_code_view_projects_definition_to_wire_shape():
    view = define_code_view(
        InstructionDefinition(address=Address(0x14000A), size=5)
    )

    assert view == {
        "address": "0x14000a",
        "ok": True,
        "size": 5,
    }


# --------------------------------------------------------------------------- #
# Registered tools: annotations, invocation, and isError translation
# --------------------------------------------------------------------------- #


def _register_set_op_type(use_case: SetOpTypeUseCase) -> Registry:
    registry = Registry()
    register_set_op_type(
        registry, set_op_type_use_case=use_case, executor=InlineExecutor()
    )
    return registry


def _register_define_code(use_case: DefineCodeUseCase) -> Registry:
    registry = Registry()
    register_define_code(
        registry, define_code_use_case=use_case, executor=InlineExecutor()
    )
    return registry


def test_set_op_type_tool_is_advertised_as_mutating():
    registry = _register_set_op_type(
        SetOpTypeUseCase(_FakeOperandGateway(), _FakeDatabaseGateway())
    )

    spec = registry.get_tool("set_op_type")
    assert spec is not None
    # ``@registry.mutating`` flips the default read-only advertisement off.
    assert spec.annotations["readOnlyHint"] is False
    # A representation change is not flagged destructive.
    assert "destructiveHint" not in spec.annotations


def test_define_code_tool_is_advertised_as_mutating():
    registry = _register_define_code(
        DefineCodeUseCase(_FakeInstructionGateway(), _FakeDatabaseGateway())
    )

    spec = registry.get_tool("define_code")
    assert spec is not None
    assert spec.annotations["readOnlyHint"] is False
    assert "destructiveHint" not in spec.annotations


def test_set_op_type_tool_invocation_returns_view():
    operands = _FakeOperandGateway()
    spec = _register_set_op_type(
        SetOpTypeUseCase(operands, _FakeDatabaseGateway())
    ).get_tool("set_op_type")

    result = spec.invoke(address="0x401000", operand=1, type="chr")

    assert result == {
        "address": "0x401000",
        "operand": 1,
        "type": "char",
        "ok": True,
    }
    assert operands.calls == [(0x401000, 1, "char")]


def test_define_code_tool_invocation_returns_view():
    instructions = _FakeInstructionGateway(sizes={0x401000: 4})
    spec = _register_define_code(
        DefineCodeUseCase(instructions, _FakeDatabaseGateway())
    ).get_tool("define_code")

    result = spec.invoke(address="0x401000")

    assert result == {
        "address": "0x401000",
        "ok": True,
        "size": 4,
    }
    assert instructions.defined == [0x401000]


def test_set_op_type_tool_invocation_surfaces_refusal_as_tool_error():
    operands = _FakeOperandGateway(refuse={(0x401000, 3)})
    spec = _register_set_op_type(
        SetOpTypeUseCase(operands, _FakeDatabaseGateway())
    ).get_tool("set_op_type")

    # A refused tag is a per-call failure (isError), not a protocol fault.
    with pytest.raises(ToolError):
        spec.invoke(address="0x401000", operand=3, type="hex")


def test_set_op_type_tool_invocation_surfaces_unknown_type_as_tool_error():
    spec = _register_set_op_type(
        SetOpTypeUseCase(_FakeOperandGateway(), _FakeDatabaseGateway())
    ).get_tool("set_op_type")

    with pytest.raises(ToolError):
        spec.invoke(address="0x401000", operand=0, type="bogus")


def test_set_op_type_tool_invocation_surfaces_unresolvable_address_as_tool_error():
    spec = _register_set_op_type(
        SetOpTypeUseCase(_FakeOperandGateway(), _FakeDatabaseGateway())
    ).get_tool("set_op_type")

    with pytest.raises(ToolError):
        spec.invoke(address="nonexistent_symbol", operand=0, type="hex")


def test_define_code_tool_invocation_surfaces_refusal_as_tool_error():
    instructions = _FakeInstructionGateway(refuse={0x401000})
    spec = _register_define_code(
        DefineCodeUseCase(instructions, _FakeDatabaseGateway())
    ).get_tool("define_code")

    with pytest.raises(ToolError):
        spec.invoke(address="0x401000")


def test_define_code_tool_invocation_surfaces_unresolvable_address_as_tool_error():
    spec = _register_define_code(
        DefineCodeUseCase(_FakeInstructionGateway(), _FakeDatabaseGateway())
    ).get_tool("define_code")

    with pytest.raises(ToolError):
        spec.invoke(address="nonexistent_symbol")
