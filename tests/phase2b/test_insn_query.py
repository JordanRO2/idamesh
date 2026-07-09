"""Unit tests for ``insn_query`` — a filtered read over a function's instructions.

The whole slice is exercised off-host over *synthetic* decoded instructions, so the
mnemonic/operand query is proven with no disassembler present:

* the authored feature projection ``_features`` — the mnemonic, the set of operand
  *kinds* present, and the set of registers touched folded to their canonical 64-bit
  family (a phrase contributes its base and index registers too);
* the ``_clamp_limit`` bound;
* the :class:`InsnQueryUseCase` — driven by fake decode / function / database
  gateways so anchor resolution, whole-function decoding, the mnemonic / operand-kind
  / operand-register filters, their conjunction, the ``limit`` / ``truncated`` cap, and
  the degenerate (empty / no-name / decoder-failure) paths are all asserted; and
* the catalog projection and read-only registration — the flat ``0x``-hex wire shape
  and the tool wiring onto the kernel thread without write affinity.

Every filter is a conjunction of pure predicates over the projected feature mapping,
and register matching is on the canonical family so a sub-register filter (``eax``)
also matches a full-register use (``rax``); these tests pin that behaviour.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Sequence, TypeVar

import pytest

from idamesh.application.contexts.insn_query import (
    InsnQueryUseCase,
    _clamp_limit,
    _features,
)
from idamesh.application.dto.insn_query import (
    DEFAULT_INSN_QUERY_LIMIT,
    INSN_OPERAND_KINDS,
    MAX_INSN_QUERY_LIMIT,
    InsnQueryCommand,
    InsnQueryResult,
)
from idamesh.domain.entities.decoded_instruction import (
    DecodedInstruction,
    OPERAND_KIND_IMM,
    OPERAND_KIND_MEM,
    OPERAND_KIND_PHRASE,
    OPERAND_KIND_REG,
    Operand,
)
from idamesh.domain.entities.function import Function
from idamesh.domain.values.address import Address, Selector
from idamesh.interface.catalog.insn_query import (
    insn_match_view,
    insn_query_view,
    register_insn_query,
)
from idamesh.interface.mcp.registry import Registry

T = TypeVar("T")


# -- decoded-instruction builders -------------------------------------------


def _reg(index: int, name: str, *, read: bool = False, write: bool = False) -> Operand:
    """A register operand (``rax`` …)."""
    return Operand(
        index=index,
        kind=OPERAND_KIND_REG,
        text=name,
        reg=name,
        is_read=read,
        is_write=write,
    )


def _imm(index: int, value: int) -> Operand:
    """An immediate/constant operand."""
    return Operand(
        index=index,
        kind=OPERAND_KIND_IMM,
        text=hex(value),
        value=value,
        is_read=True,
    )


def _mem(index: int, addr: int, *, read: bool = False, write: bool = False) -> Operand:
    """A direct (global) memory operand at an absolute address."""
    return Operand(
        index=index,
        kind=OPERAND_KIND_MEM,
        text=f"[{hex(addr)}]",
        value=addr,
        is_read=read,
        is_write=write,
    )


def _phrase(
    index: int,
    disp: int,
    *,
    base: str = "rbp",
    idx_reg: Optional[str] = None,
    read: bool = False,
    write: bool = False,
) -> Operand:
    """A ``[base(±index)±disp]`` phrase — a computed (typically stack) address."""
    sign = "+" if disp >= 0 else "-"
    return Operand(
        index=index,
        kind=OPERAND_KIND_PHRASE,
        text=f"[{base}{sign}{abs(disp):#x}]",
        base_reg=base,
        index_reg=idx_reg,
        disp=disp,
        is_read=read,
        is_write=write,
    )


def _insn(ea: int, mnemonic: str, *operands: Operand) -> DecodedInstruction:
    return DecodedInstruction(
        ea=Address(ea), mnemonic=mnemonic, operands=tuple(operands)
    )


# -- fakes for the use-case -------------------------------------------------


class _FakeDecoder:
    """An ``InstructionDecodeGateway`` returning a fixed instruction list.

    Records the address every ``decode_function`` call was made with, so the
    use-case is shown to decode the *containing function* at the resolved anchor.
    """

    def __init__(self, instructions: Sequence[DecodedInstruction]) -> None:
        self._instructions = list(instructions)
        self.decoded_for: List[int] = []

    def decode_function(self, ea: Address) -> List[DecodedInstruction]:
        self.decoded_for.append(ea.value)
        return list(self._instructions)


class _RaisingDecoder:
    """An ``InstructionDecodeGateway`` modelling an address in no function."""

    def decode_function(self, ea: Address) -> List[DecodedInstruction]:
        raise ValueError("no function contains this address")


class _FakeFunctions:
    """A ``FunctionRepository`` whose point lookup returns a preset function."""

    def __init__(self, containing: Optional[Function]) -> None:
        self._containing = containing

    def get_containing(self, ea: Address) -> Optional[Function]:
        return self._containing

    def get(self, ea: Address) -> Optional[Function]:  # pragma: no cover - unused
        return None

    def count(self) -> int:  # pragma: no cover - unused
        return 0

    def list(self, page):  # pragma: no cover - unused
        raise NotImplementedError


class _FakeDatabase:
    """A ``DatabaseGateway`` resolving hex/decimal directly and symbols by map."""

    def __init__(self, symbols: Optional[dict] = None) -> None:
        self._symbols = symbols or {}

    def resolve(self, selector: Selector) -> Address:
        return selector.resolve(self)

    def resolve_symbol(self, name: str) -> Optional[int]:
        return self._symbols.get(name)

    def is_open(self) -> bool:  # pragma: no cover - unused
        return True

    def metadata(self):  # pragma: no cover - unused
        raise NotImplementedError


class _InlineExecutor:
    """A ``MainThreadExecutor`` that runs jobs inline, recording write affinity."""

    def __init__(self) -> None:
        self.write_flags: List[bool] = []

    def run(self, job: Callable[[], T], *, write: bool = False) -> T:
        self.write_flags.append(write)
        return job()

    def on_kernel_thread(self) -> bool:  # pragma: no cover - unused
        return True


# -- shared fixtures --------------------------------------------------------


def _fixture_instructions() -> List[DecodedInstruction]:
    """A small function touching every operand kind and a folded sub-register.

    ==========  =====================  ================  ===================
    address     instruction            operand kinds     registers (folded)
    ==========  =====================  ================  ===================
    0x1000      ``mov rax, 5``         reg, imm          rax
    0x1004      ``add ebx, eax``       reg               rbx, rax
    0x1008      ``mov [rbp-8], rax``   phrase, reg       rbp, rax
    0x100C      ``mov rcx, [0x140A0]`` reg, mem          rcx
    0x1010      ``ret``                (none)            (none)
    ==========  =====================  ================  ===================
    """
    return [
        _insn(0x1000, "mov", _reg(0, "rax", write=True), _imm(1, 5)),
        _insn(0x1004, "add", _reg(0, "ebx", read=True, write=True), _reg(1, "eax", read=True)),
        _insn(0x1008, "mov", _phrase(0, -8, base="rbp", write=True), _reg(1, "rax", read=True)),
        _insn(0x100C, "mov", _reg(0, "rcx", write=True), _mem(1, 0x140A0, read=True)),
        _insn(0x1010, "ret"),
    ]


def _sample_function() -> Function:
    return Function(ea=Address(0x1000), name="sub_1000", size=0x14)


def _use_case(
    instrs: Sequence[DecodedInstruction],
    *,
    func: Optional[Function],
    symbols: Optional[dict] = None,
) -> "tuple[InsnQueryUseCase, _FakeDecoder]":
    decoder = _FakeDecoder(instrs)
    use_case = InsnQueryUseCase(decoder, _FakeFunctions(func), _FakeDatabase(symbols))
    return use_case, decoder


def _addrs(result: InsnQueryResult) -> List[int]:
    """Reduce a result to the addresses of its matched instructions."""
    return [m.ea.value for m in result.matches]


# ==========================================================================
# _features — the authored projection the query evaluates over
# ==========================================================================


def test_features_projects_mnemonic_kinds_and_reg_families():
    insn = _insn(
        0x1000, "add", _reg(0, "ebx", read=True, write=True), _reg(1, "eax", read=True)
    )

    features = _features(insn)

    assert features["mnemonic"] == "add"
    assert features["operand_kinds"] == {"reg"}
    # eax/ebx fold onto their 64-bit families.
    assert features["regs"] == {"rbx", "rax"}


def test_features_collects_phrase_base_and_index_registers():
    insn = _insn(
        0x2000,
        "mov",
        _reg(0, "rax", write=True),
        _phrase(1, -8, base="rbp", idx_reg="rsi", read=True),
    )

    features = _features(insn)

    assert features["operand_kinds"] == {"reg", "phrase"}
    assert features["regs"] == {"rax", "rbp", "rsi"}


def test_features_of_a_no_operand_instruction_is_empty():
    features = _features(_insn(0x3000, "ret"))

    assert features["mnemonic"] == "ret"
    assert features["operand_kinds"] == set()
    assert features["regs"] == set()


def test_features_immediate_and_global_contribute_no_registers():
    insn = _insn(0x4000, "mov", _mem(0, 0x140A0, write=True), _imm(1, 7))

    features = _features(insn)

    assert features["operand_kinds"] == {"mem", "imm"}
    assert features["regs"] == set()


# ==========================================================================
# _clamp_limit
# ==========================================================================


def test_clamp_limit_bounds_to_zero_and_the_ceiling():
    assert _clamp_limit(-1, 2000) == 0
    assert _clamp_limit(0, 2000) == 0
    assert _clamp_limit(50, 2000) == 50
    assert _clamp_limit(2000, 2000) == 2000
    assert _clamp_limit(9999, 2000) == 2000


# ==========================================================================
# InsnQueryUseCase — filtering
# ==========================================================================


def test_no_filter_returns_every_instruction_in_order():
    use_case, _ = _use_case(_fixture_instructions(), func=_sample_function())

    result = use_case.execute(InsnQueryCommand(address="0x1000"))

    assert isinstance(result, InsnQueryResult)
    assert result.function == "sub_1000"
    assert _addrs(result) == [0x1000, 0x1004, 0x1008, 0x100C, 0x1010]
    assert result.truncated is False


def test_mnemonic_filter_is_exact_and_case_insensitive():
    use_case, _ = _use_case(_fixture_instructions(), func=_sample_function())

    result = use_case.execute(InsnQueryCommand(address="0x1000", mnemonic="MOV"))

    # The three ``mov``s, not the ``add`` or the ``ret``.
    assert _addrs(result) == [0x1000, 0x1008, 0x100C]


def test_operand_kind_immediate_filter():
    use_case, _ = _use_case(_fixture_instructions(), func=_sample_function())

    result = use_case.execute(InsnQueryCommand(address="0x1000", operand_kind="imm"))

    assert _addrs(result) == [0x1000]


def test_operand_kind_memory_filter():
    use_case, _ = _use_case(_fixture_instructions(), func=_sample_function())

    result = use_case.execute(InsnQueryCommand(address="0x1000", operand_kind="mem"))

    assert _addrs(result) == [0x100C]


def test_operand_kind_phrase_filter():
    use_case, _ = _use_case(_fixture_instructions(), func=_sample_function())

    result = use_case.execute(InsnQueryCommand(address="0x1000", operand_kind="phrase"))

    assert _addrs(result) == [0x1008]


def test_operand_kind_register_filter_excludes_the_operandless_ret():
    use_case, _ = _use_case(_fixture_instructions(), func=_sample_function())

    result = use_case.execute(InsnQueryCommand(address="0x1000", operand_kind="reg"))

    assert _addrs(result) == [0x1000, 0x1004, 0x1008, 0x100C]


def test_operand_kind_is_normalized_to_lower_case():
    use_case, _ = _use_case(_fixture_instructions(), func=_sample_function())

    result = use_case.execute(InsnQueryCommand(address="0x1000", operand_kind="IMM"))

    assert _addrs(result) == [0x1000]


def test_operand_reg_matches_the_canonical_family():
    use_case, _ = _use_case(_fixture_instructions(), func=_sample_function())

    result = use_case.execute(InsnQueryCommand(address="0x1000", operand_reg="rax"))

    # 0x1004 references eax, which folds onto rax and so matches.
    assert _addrs(result) == [0x1000, 0x1004, 0x1008]


def test_operand_reg_subregister_filter_matches_a_full_register_use():
    use_case, _ = _use_case(_fixture_instructions(), func=_sample_function())

    # eax (sub-register) filter must also match the full-register rax uses.
    result = use_case.execute(InsnQueryCommand(address="0x1000", operand_reg="eax"))

    assert _addrs(result) == [0x1000, 0x1004, 0x1008]


def test_operand_reg_matches_phrase_base_and_index_registers():
    instrs = [
        _insn(
            0x2000,
            "mov",
            _reg(0, "rax", write=True),
            _phrase(1, -8, base="rbp", idx_reg="rsi", read=True),
        )
    ]
    use_case, _ = _use_case(instrs, func=_sample_function())

    def matched(reg: str) -> List[int]:
        return _addrs(use_case.execute(InsnQueryCommand(address="0x2000", operand_reg=reg)))

    assert matched("rax") == [0x2000]  # destination register
    assert matched("rbp") == [0x2000]  # phrase base
    assert matched("rsi") == [0x2000]  # phrase index
    assert matched("rdi") == []        # untouched register


def test_filters_are_conjoined():
    use_case, _ = _use_case(_fixture_instructions(), func=_sample_function())

    result = use_case.execute(
        InsnQueryCommand(address="0x1000", mnemonic="mov", operand_reg="rax")
    )

    # mov AND touches-rax: 0x1004 (add) is excluded despite touching rax.
    assert _addrs(result) == [0x1000, 0x1008]


def test_unknown_operand_kind_raises_value_error():
    use_case, _ = _use_case(_fixture_instructions(), func=_sample_function())

    with pytest.raises(ValueError):
        use_case.execute(InsnQueryCommand(address="0x1000", operand_kind="bogus"))


# ==========================================================================
# InsnQueryUseCase — limit / truncation
# ==========================================================================


def test_limit_truncates_when_matches_remain():
    use_case, _ = _use_case(_fixture_instructions(), func=_sample_function())

    result = use_case.execute(InsnQueryCommand(address="0x1000", limit=2))

    assert _addrs(result) == [0x1000, 0x1004]
    assert result.truncated is True


def test_limit_equal_to_match_count_is_not_truncated():
    use_case, _ = _use_case(_fixture_instructions(), func=_sample_function())

    result = use_case.execute(InsnQueryCommand(address="0x1000", limit=5))

    assert len(result.matches) == 5
    assert result.truncated is False


def test_limit_applies_to_the_filtered_stream():
    use_case, _ = _use_case(_fixture_instructions(), func=_sample_function())

    capped = use_case.execute(InsnQueryCommand(address="0x1000", mnemonic="mov", limit=2))
    assert _addrs(capped) == [0x1000, 0x1008]
    assert capped.truncated is True

    exact = use_case.execute(InsnQueryCommand(address="0x1000", mnemonic="mov", limit=3))
    assert _addrs(exact) == [0x1000, 0x1008, 0x100C]
    assert exact.truncated is False


def test_negative_limit_is_clamped_to_zero():
    use_case, _ = _use_case(_fixture_instructions(), func=_sample_function())

    result = use_case.execute(InsnQueryCommand(address="0x1000", limit=-1))

    # Nothing is returned, but matches exist beyond the (zero) cap.
    assert result.matches == ()
    assert result.truncated is True


def test_oversized_limit_is_clamped_to_the_ceiling():
    use_case, _ = _use_case(_fixture_instructions(), func=_sample_function())

    result = use_case.execute(
        InsnQueryCommand(address="0x1000", limit=MAX_INSN_QUERY_LIMIT * 1000)
    )

    assert len(result.matches) == 5
    assert result.truncated is False


# ==========================================================================
# InsnQueryUseCase — resolution, decoding, degenerate inputs
# ==========================================================================


def test_resolves_a_symbol_selector_and_decodes_the_containing_function():
    use_case, decoder = _use_case(
        _fixture_instructions(), func=_sample_function(), symbols={"main": 0x1000}
    )

    result = use_case.execute(InsnQueryCommand(address="main"))

    assert result.function == "sub_1000"
    assert decoder.decoded_for == [0x1000]


def test_decodes_at_the_resolved_anchor_even_past_the_entry():
    use_case, decoder = _use_case(_fixture_instructions(), func=_sample_function())

    use_case.execute(InsnQueryCommand(address="0x1008"))

    # The whole function is decoded from the resolved anchor address.
    assert decoder.decoded_for == [0x1008]


def test_address_in_no_named_function_still_returns_matches_with_no_name():
    use_case, _ = _use_case(_fixture_instructions(), func=None)

    result = use_case.execute(InsnQueryCommand(address="0x1000"))

    assert result.function is None
    assert _addrs(result) == [0x1000, 0x1004, 0x1008, 0x100C, 0x1010]


def test_decoder_failure_propagates():
    use_case = InsnQueryUseCase(
        _RaisingDecoder(), _FakeFunctions(None), _FakeDatabase()
    )

    with pytest.raises(ValueError):
        use_case.execute(InsnQueryCommand(address="0x1000"))


def test_empty_function_is_a_valid_empty_result():
    use_case, _ = _use_case([], func=_sample_function())

    result = use_case.execute(InsnQueryCommand(address="0x1000"))

    assert result.matches == ()
    assert result.function == "sub_1000"
    assert result.truncated is False


# ==========================================================================
# DTO constants — the frozen contract values
# ==========================================================================


def test_dto_constants_match_the_frozen_contract():
    assert DEFAULT_INSN_QUERY_LIMIT == 200
    assert MAX_INSN_QUERY_LIMIT == 2000
    assert INSN_OPERAND_KINDS == ("any", "reg", "imm", "mem", "phrase")


# ==========================================================================
# View projection
# ==========================================================================


def test_insn_match_view_projects_flat_hex_shape():
    insn = _insn(
        0x14001A,
        "add",
        _reg(0, "ebx", read=True, write=True),
        _reg(1, "eax", read=True),
    )

    assert insn_match_view(insn) == {
        "address": "0x14001a",
        "mnemonic": "add",
        "text": "add ebx, eax",
    }


def test_insn_query_view_projects_result_to_wire_shape():
    result = InsnQueryResult(
        function="sub_1000",
        matches=(
            _insn(0x1000, "mov", _reg(0, "rax", write=True), _imm(1, 5)),
            _insn(0x1008, "mov", _phrase(0, -8, base="rbp", write=True), _reg(1, "rax", read=True)),
        ),
        truncated=True,
    )

    view = insn_query_view(result)

    assert view == {
        "function": "sub_1000",
        "matches": [
            {"address": "0x1000", "mnemonic": "mov", "text": "mov rax, 0x5"},
            {"address": "0x1008", "mnemonic": "mov", "text": "mov [rbp-0x8], rax"},
        ],
        "truncated": True,
    }


def test_insn_query_view_projects_an_empty_result():
    view = insn_query_view(
        InsnQueryResult(function=None, matches=(), truncated=False)
    )

    assert view == {"function": None, "matches": [], "truncated": False}


# ==========================================================================
# Catalog registration
# ==========================================================================


def _register(
    instrs: Sequence[DecodedInstruction],
    func: Optional[Function],
    executor: _InlineExecutor,
) -> Registry:
    registry = Registry()
    use_case = InsnQueryUseCase(
        _FakeDecoder(instrs), _FakeFunctions(func), _FakeDatabase()
    )
    register_insn_query(registry, insn_query_use_case=use_case, executor=executor)
    return registry


def test_insn_query_is_registered_read_only():
    registry = _register(_fixture_instructions(), _sample_function(), _InlineExecutor())

    spec = registry.get_tool("insn_query")

    assert spec is not None
    # Decoding and filtering a function mutates nothing.
    assert spec.annotations["readOnlyHint"] is True
    assert spec.output_schema is not None


def test_registered_invocation_returns_the_wire_shape_read_only():
    executor = _InlineExecutor()
    registry = _register(_fixture_instructions(), _sample_function(), executor)

    spec = registry.get_tool("insn_query")
    out = spec.invoke(address="0x1000", mnemonic="mov", limit=2)

    assert out["function"] == "sub_1000"
    assert out["truncated"] is True
    assert out["matches"] == [
        {"address": "0x1000", "mnemonic": "mov", "text": "mov rax, 0x5"},
        {"address": "0x1008", "mnemonic": "mov", "text": "mov [rbp-0x8], rax"},
    ]
    # A read-only tool is marshalled onto the kernel thread without write affinity.
    assert executor.write_flags == [False]
