"""Unit tests for ``detect_stack_strings`` and the decoded-instruction model (no IDA).

Four layers are exercised entirely off-host, over *synthetic* decoded instructions:

* the pure decoded-instruction model — :func:`canonical_reg` register-family
  folding, :meth:`Operand.stack_slot` slot identification, and the
  :class:`DecodedInstruction` text/operand accessors;
* the pure :class:`StackStringService` — reconstructing a string from immediate
  stores into consecutive stack slots, rejecting non-printable bytes / gaps /
  short runs, honouring the store width and later-store-wins overwrites, and
  returning an empty (valid, sparse) result;
* the :class:`DetectStackStringsUseCase` — driven by a fake decode gateway, a
  fake function repository, and a fake database, so single-function scoping,
  the bounded whole-database sweep, decode-failure skipping, and the scan/match
  bounds are asserted with no IDA present; and
* the catalog projection and registration — the flat ``0x``-hex wire shape and
  the read-only tool wiring.

Every instruction here is hand-built; no disassembler is involved, which is the
whole point of the pure decoded model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, TypeVar

import pytest

from idamesh.application.contexts.detect_stack_strings import (
    DetectStackStringsUseCase,
)
from idamesh.application.dto.detect_stack_strings import (
    MAX_SCAN_FUNCTIONS,
    MAX_STACK_STRINGS,
    DetectStackStringsCommand,
    DetectStackStringsResult,
)
from idamesh.domain.entities.decoded_instruction import (
    DecodedInstruction,
    Operand,
    OPERAND_KIND_IMM,
    OPERAND_KIND_MEM,
    OPERAND_KIND_PHRASE,
    OPERAND_KIND_REG,
    STACK_REGS,
    canonical_reg,
)
from idamesh.domain.entities.function import Function
from idamesh.domain.entities.stack_string import StackString
from idamesh.domain.services.stack_strings import (
    DEFAULT_MIN_LENGTH,
    StackStringService,
)
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import MAX_COUNT, Page, PageRequest
from idamesh.interface.catalog.detect_stack_strings import (
    detect_stack_strings_view,
    register_detect_stack_strings,
    stack_string_view,
)
from idamesh.interface.mcp.registry import Registry

T = TypeVar("T")


# -- instruction builders ---------------------------------------------------


def _imm(value: int, *, index: int = 1, size: Optional[int] = None) -> Operand:
    """An immediate source operand carrying ``value``."""
    return Operand(
        index=index,
        kind=OPERAND_KIND_IMM,
        text=hex(value),
        value=value,
        size=size,
        is_read=True,
    )


def _slot(
    disp: int,
    *,
    index: int = 0,
    base: str = "rsp",
    size: Optional[int] = None,
    is_write: bool = True,
    index_reg: Optional[str] = None,
) -> Operand:
    """A ``[base±disp]`` phrase destination operand naming a stack slot."""
    sign = "+" if disp >= 0 else "-"
    return Operand(
        index=index,
        kind=OPERAND_KIND_PHRASE,
        text=f"[{base}{sign}{abs(disp):#x}]",
        base_reg=base,
        index_reg=index_reg,
        disp=disp,
        size=size,
        is_write=is_write,
        is_read=False,
    )


def _store(
    ea: int,
    disp: int,
    value: int,
    *,
    base: str = "rsp",
    size: int = 1,
    mnem: str = "mov",
    dest_write: bool = True,
) -> DecodedInstruction:
    """A ``mov [base+disp], imm`` immediate-to-stack-slot store."""
    return DecodedInstruction(
        ea=Address(ea),
        mnemonic=mnem,
        operands=(
            _slot(disp, base=base, size=size, is_write=dest_write),
            _imm(value, size=size),
        ),
    )


def _char_run(
    start_ea: int, start_disp: int, text: str, *, base: str = "rsp"
) -> List[DecodedInstruction]:
    """One single-byte store per character across consecutive stack slots."""
    return [
        _store(start_ea + i, start_disp + i, ord(ch), base=base, size=1)
        for i, ch in enumerate(text)
    ]


# ==========================================================================
# The decoded-instruction model
# ==========================================================================


@pytest.mark.parametrize(
    "alias, family",
    [
        ("rax", "rax"),
        ("eax", "rax"),
        ("ax", "rax"),
        ("al", "rax"),
        ("ah", "rax"),
        ("edi", "rdi"),
        ("sil", "rsi"),
        ("esp", "rsp"),
        ("ebp", "rbp"),
        ("r8d", "r8"),
        ("r15b", "r15"),
        ("r12w", "r12"),
    ],
)
def test_canonical_reg_folds_sub_registers_to_the_64bit_family(alias, family):
    assert canonical_reg(alias) == family


def test_canonical_reg_is_case_and_whitespace_insensitive():
    assert canonical_reg("  EAX ") == "rax"
    assert canonical_reg("RsP") == "rsp"


def test_canonical_reg_unknown_register_is_its_own_lowercased_family():
    # A vector/segment register we do not model is returned lowercased, unchanged.
    assert canonical_reg("XMM0") == "xmm0"
    assert canonical_reg("fs") == "fs"


def test_canonical_reg_none_is_none():
    assert canonical_reg(None) is None


def test_stack_regs_are_the_stack_and_frame_pointers():
    assert STACK_REGS == frozenset({"rsp", "esp", "sp", "rbp", "ebp", "bp"})


@pytest.mark.parametrize("base", ["rsp", "esp", "sp", "rbp", "ebp", "bp"])
def test_stack_slot_identifies_every_stack_base(base):
    assert _slot(0x20, base=base).stack_slot() == 0x20


def test_stack_slot_returns_negative_frame_displacement():
    assert _slot(-8, base="rbp").stack_slot() == -8


def test_stack_slot_defaults_absent_displacement_to_zero():
    op = Operand(index=0, kind=OPERAND_KIND_PHRASE, text="[rsp]", base_reg="rsp")
    assert op.stack_slot() == 0


def test_stack_slot_rejects_indexed_access():
    # An indexed phrase is not a simple scalar slot.
    assert _slot(0x10, base="rsp", index_reg="rcx").stack_slot() is None


def test_stack_slot_rejects_non_stack_base():
    assert _slot(0x10, base="rax").stack_slot() is None


def test_stack_slot_rejects_non_phrase_operands():
    reg = Operand(index=0, kind=OPERAND_KIND_REG, text="rax", reg="rax")
    imm = Operand(index=1, kind=OPERAND_KIND_IMM, text="0x1", value=1)
    mem = Operand(index=0, kind=OPERAND_KIND_MEM, text="ds:0x600000", value=0x600000)
    assert reg.stack_slot() is None
    assert imm.stack_slot() is None
    assert mem.stack_slot() is None


def test_stack_slot_rejects_phrase_with_no_base():
    op = Operand(index=0, kind=OPERAND_KIND_PHRASE, text="[0x10]", disp=0x10)
    assert op.stack_slot() is None


def test_decoded_instruction_text_renders_mnemonic_and_operands():
    insn = _store(0x1000, 0, 0x50)
    assert insn.text == "mov [rsp+0x0], 0x50"


def test_decoded_instruction_text_of_operandless_is_just_the_mnemonic():
    assert DecodedInstruction(ea=Address(0x1000), mnemonic="ret").text == "ret"


def test_decoded_instruction_operand_lookup_by_index():
    insn = _store(0x1000, 4, 0x41)
    assert insn.operand(0).kind == OPERAND_KIND_PHRASE
    assert insn.operand(1).kind == OPERAND_KIND_IMM
    # Out of range yields None rather than raising.
    assert insn.operand(5) is None


# ==========================================================================
# StackStringService — the pure reconstruction algorithm
# ==========================================================================


def test_reconstructs_string_from_single_byte_stores():
    service = StackStringService()
    matches = service.detect(_char_run(0x1000, 0, "PASS"))
    assert [m.value for m in matches] == ["PASS"]
    # The finding anchors at the earliest store contributing a byte to the run.
    assert matches[0].address == Address(0x1000)


def test_reconstructs_string_from_a_multi_byte_immediate_store():
    # mov dword [rsp+0], 0x53534150 lays down 0x50 0x41 0x53 0x53 = "PASS".
    service = StackStringService()
    insns = [_store(0x2000, 0, 0x53534150, size=4)]
    matches = service.detect(insns)
    assert [m.value for m in matches] == ["PASS"]
    assert matches[0].address == Address(0x2000)


def test_store_width_is_driven_by_the_destination_size():
    # A single 4-byte store of 0x44434241 -> "ABCD" (little-endian).
    service = StackStringService()
    matches = service.detect([_store(0x3000, 0, 0x44434241, size=4)])
    assert [m.value for m in matches] == ["ABCD"]


def test_function_name_is_propagated_onto_findings():
    service = StackStringService()
    matches = service.detect(_char_run(0x1000, 0, "PASS"), function="decrypt")
    assert matches[0].function == "decrypt"


def test_a_zero_byte_terminates_a_run():
    service = StackStringService()
    # 'A' 'B' NUL 'C' 'D' at consecutive slots.
    insns = [
        _store(0x1000, 0, ord("A")),
        _store(0x1001, 1, ord("B")),
        _store(0x1002, 2, 0x00),
        _store(0x1003, 3, ord("C")),
        _store(0x1004, 4, ord("D")),
    ]
    matches = service.detect(insns, min_length=2)
    assert sorted(m.value for m in matches) == ["AB", "CD"]


def test_a_non_printable_byte_breaks_a_run():
    service = StackStringService()
    insns = [
        _store(0x1000, 0, ord("A")),
        _store(0x1001, 1, ord("B")),
        _store(0x1002, 2, 0x01),  # SOH — outside the printable band
        _store(0x1003, 3, ord("C")),
        _store(0x1004, 4, ord("D")),
    ]
    matches = service.detect(insns, min_length=2)
    assert sorted(m.value for m in matches) == ["AB", "CD"]


def test_a_gap_in_slots_splits_into_separate_runs():
    service = StackStringService()
    # "ABC" at 0..2 and "XYZ" at 10..12 — non-adjacent slots are distinct strings.
    insns = _char_run(0x1000, 0, "ABC") + _char_run(0x1010, 10, "XYZ")
    matches = service.detect(insns, min_length=3)
    assert sorted(m.value for m in matches) == ["ABC", "XYZ"]


def test_runs_shorter_than_min_length_are_dropped():
    service = StackStringService()
    matches = service.detect(_char_run(0x1000, 0, "ABC"), min_length=4)
    assert matches == []


def test_default_min_length_is_four():
    service = StackStringService()
    # "PAS" (3) is dropped by the default threshold; "PASS" (4) is kept.
    assert service.detect(_char_run(0x1000, 0, "PAS")) == []
    assert [m.value for m in service.detect(_char_run(0x1000, 0, "PASS"))] == ["PASS"]
    assert DEFAULT_MIN_LENGTH == 4


def test_non_positive_min_length_falls_back_to_the_default():
    service = StackStringService()
    # min_length<=0 uses the default (4): the 3-char run is still dropped.
    assert service.detect(_char_run(0x1000, 0, "PAS"), min_length=0) == []
    assert [
        m.value for m in service.detect(_char_run(0x1000, 0, "PASS"), min_length=-1)
    ] == ["PASS"]


def test_later_store_to_the_same_slot_wins():
    service = StackStringService()
    # Slot 0 is first written 'X', then overwritten 'P'; the later value wins.
    insns = [
        _store(0x1000, 0, ord("X")),
        _store(0x1004, 0, ord("P")),
        _store(0x1005, 1, ord("A")),
        _store(0x1006, 2, ord("S")),
        _store(0x1007, 3, ord("S")),
    ]
    matches = service.detect(insns)
    assert [m.value for m in matches] == ["PASS"]


def test_non_store_mnemonics_are_ignored():
    service = StackStringService()
    # An arithmetic op into a stack slot is not an immediate store we reconstruct.
    insns = [
        DecodedInstruction(
            ea=Address(0x1000 + i),
            mnemonic="add",
            operands=(_slot(i), _imm(ord(ch))),
        )
        for i, ch in enumerate("PASS")
    ]
    assert service.detect(insns) == []


def test_mnemonic_matching_is_case_insensitive():
    service = StackStringService()
    insns = [
        _store(0x1000 + i, i, ord(ch), mnem="MOV") for i, ch in enumerate("PASS")
    ]
    assert [m.value for m in service.detect(insns)] == ["PASS"]


def test_stores_to_a_global_address_are_ignored():
    service = StackStringService()
    # mov [0x600000], imm — an absolute (non-stack) memory destination.
    insns = [
        DecodedInstruction(
            ea=Address(0x1000 + i),
            mnemonic="mov",
            operands=(
                Operand(
                    index=0,
                    kind=OPERAND_KIND_MEM,
                    text="ds:0x600000",
                    value=0x600000 + i,
                    is_write=True,
                ),
                _imm(ord(ch)),
            ),
        )
        for i, ch in enumerate("PASS")
    ]
    assert service.detect(insns) == []


def test_stores_to_a_register_are_ignored():
    service = StackStringService()
    insns = [
        DecodedInstruction(
            ea=Address(0x1000),
            mnemonic="mov",
            operands=(
                Operand(
                    index=0,
                    kind=OPERAND_KIND_REG,
                    text="rax",
                    reg="rax",
                    is_write=True,
                ),
                _imm(0x50505050, size=4),
            ),
        )
    ]
    assert service.detect(insns) == []


def test_a_read_only_stack_operand_is_not_a_store():
    service = StackStringService()
    # A stack phrase that the instruction reads (not writes) cannot be a store.
    insns = [_store(0x1000 + i, i, ord(ch), dest_write=False) for i, ch in enumerate("PASS")]
    assert service.detect(insns) == []


def test_a_non_immediate_source_is_not_a_store():
    service = StackStringService()
    # mov [rsp+0], rax — register source, not an immediate.
    insns = [
        DecodedInstruction(
            ea=Address(0x1000),
            mnemonic="mov",
            operands=(
                _slot(0),
                Operand(index=1, kind=OPERAND_KIND_REG, text="rax", reg="rax", is_read=True),
            ),
        )
    ]
    assert service.detect(insns) == []


def test_empty_instruction_stream_yields_no_strings():
    assert StackStringService().detect([]) == []


def test_stores_on_distinct_base_registers_do_not_merge():
    service = StackStringService()
    # Same displacements but different base registers are independent buffers.
    insns = _char_run(0x1000, 0, "ABCD", base="rsp") + _char_run(
        0x2000, 0, "WXYZ", base="rbp"
    )
    matches = service.detect(insns)
    assert sorted(m.value for m in matches) == ["ABCD", "WXYZ"]


def test_results_are_ordered_by_anchor_address_then_value():
    service = StackStringService()
    # Two runs authored out of address order; the result is sorted by anchor.
    insns = _char_run(0x2000, 20, "ZZZZ") + _char_run(0x1000, 0, "AAAA")
    matches = service.detect(insns)
    assert [(m.address.value, m.value) for m in matches] == [
        (0x1000, "AAAA"),
        (0x2000, "ZZZZ"),
    ]


# ==========================================================================
# fakes for the use-case
# ==========================================================================


class _FakeDecodeGateway:
    """An in-memory ``InstructionDecodeGateway`` keyed by function entry EA.

    ``by_ea`` maps a function's entry-address integer to the decoded instruction
    list :meth:`decode_function` returns for it. An entry in ``fail`` raises
    (modelling a function that cannot be decoded); an unmapped, non-failing EA
    also raises (address in no function). Every call is recorded so the sweep's
    scan bound can be asserted.
    """

    def __init__(
        self,
        by_ea: Optional[Dict[int, Sequence[DecodedInstruction]]] = None,
        *,
        fail: frozenset = frozenset(),
    ) -> None:
        self._by_ea = by_ea or {}
        self._fail = set(fail)
        self.calls: List[int] = []

    def decode_function(self, ea: Address) -> List[DecodedInstruction]:
        self.calls.append(ea.value)
        if ea.value in self._fail:
            raise ValueError(f"cannot decode function at {ea.hex()}")
        if ea.value not in self._by_ea:
            raise ValueError(f"no function contains address {ea.hex()}")
        return list(self._by_ea[ea.value])


class _FakeFunctionRepository:
    """An in-memory ``FunctionRepository`` over a fixed function list.

    ``page_size`` (when set) forces the sweep through multiple pages regardless
    of the requested count, so the paging loop is exercised; otherwise a single
    page satisfies the request.
    """

    def __init__(
        self, functions: Sequence[Function], *, page_size: Optional[int] = None
    ) -> None:
        self._functions = list(functions)
        self._page_size = page_size

    def list(self, page: PageRequest) -> Page[Function]:
        size = self._page_size if self._page_size is not None else page.count
        window = self._functions[page.offset : page.offset + size]
        end = page.offset + len(window)
        return Page(
            items=window,
            offset=page.offset,
            count=len(window),
            total=len(self._functions),
            truncated=end < len(self._functions),
        )

    def count(self) -> int:
        return len(self._functions)

    def get(self, ea: Address) -> Optional[Function]:
        for func in self._functions:
            if func.ea == ea:
                return func
        return None

    def get_containing(self, ea: Address) -> Optional[Function]:
        for func in self._functions:
            end = func.end_ea.value if func.end_ea else func.ea.value + func.size
            if func.ea.value <= ea.value < end:
                return func
        return None


class _FakeDatabaseGateway:
    """A ``DatabaseGateway`` that resolves numeric selectors and named symbols."""

    def __init__(self, symbols: Optional[Dict[str, int]] = None) -> None:
        self._symbols = symbols or {}

    def resolve(self, selector) -> Address:
        return selector.resolve(self)

    def resolve_symbol(self, name: str) -> Optional[int]:
        return self._symbols.get(name)

    def is_open(self) -> bool:
        return True

    def metadata(self):  # pragma: no cover - unused by this use-case
        raise NotImplementedError


@dataclass
class _InlineExecutor:
    """A ``MainThreadExecutor`` that runs jobs inline, recording affinity."""

    write_flags: List[bool] = field(default_factory=list)

    def run(self, job: Callable[[], T], *, write: bool = False) -> T:
        self.write_flags.append(write)
        return job()

    def on_kernel_thread(self) -> bool:
        return True


def _func(ea: int, name: str, size: int = 0x100) -> Function:
    return Function(ea=Address(ea), name=name, size=size)


def _use_case(
    decoder: _FakeDecodeGateway,
    functions: _FakeFunctionRepository,
    database: _FakeDatabaseGateway,
) -> DetectStackStringsUseCase:
    return DetectStackStringsUseCase(
        decoder, StackStringService(), functions, database
    )


# ==========================================================================
# DetectStackStringsUseCase
# ==========================================================================


def test_single_function_mode_scans_the_containing_function():
    decoder = _FakeDecodeGateway({0x401000: _char_run(0x401000, 0, "PASS")})
    functions = _FakeFunctionRepository([_func(0x401000, "decrypt")])
    database = _FakeDatabaseGateway()
    use_case = _use_case(decoder, functions, database)

    result = use_case.execute(DetectStackStringsCommand(address="0x401000"))

    assert isinstance(result, DetectStackStringsResult)
    assert [(m.value, m.function) for m in result.matches] == [("PASS", "decrypt")]
    assert result.truncated is False
    # Exactly the one containing function was decoded.
    assert decoder.calls == [0x401000]


def test_single_function_mode_resolves_a_symbol_selector():
    decoder = _FakeDecodeGateway({0x401000: _char_run(0x401000, 0, "PASS")})
    functions = _FakeFunctionRepository([_func(0x401000, "decrypt")])
    database = _FakeDatabaseGateway(symbols={"decrypt": 0x401000})
    use_case = _use_case(decoder, functions, database)

    result = use_case.execute(DetectStackStringsCommand(address="decrypt"))

    assert [m.value for m in result.matches] == ["PASS"]


def test_single_function_mode_scoped_by_an_interior_address():
    # An address inside the body (not the entry) still resolves to the function.
    decoder = _FakeDecodeGateway({0x401000: _char_run(0x401000, 0, "PASS")})
    functions = _FakeFunctionRepository([_func(0x401000, "decrypt", size=0x100)])
    database = _FakeDatabaseGateway()
    use_case = _use_case(decoder, functions, database)

    result = use_case.execute(DetectStackStringsCommand(address="0x401040"))

    assert [m.value for m in result.matches] == ["PASS"]
    assert decoder.calls == [0x401000]


def test_single_function_mode_address_in_no_function_is_an_error():
    decoder = _FakeDecodeGateway({})
    functions = _FakeFunctionRepository([])  # nothing contains the address
    database = _FakeDatabaseGateway()
    use_case = _use_case(decoder, functions, database)

    with pytest.raises(ValueError):
        use_case.execute(DetectStackStringsCommand(address="0x999999"))


def test_single_function_mode_decode_failure_propagates():
    # In scoped mode a decode failure is fatal (not silently skipped).
    decoder = _FakeDecodeGateway({}, fail=frozenset({0x401000}))
    functions = _FakeFunctionRepository([_func(0x401000, "decrypt")])
    database = _FakeDatabaseGateway()
    use_case = _use_case(decoder, functions, database)

    with pytest.raises(ValueError):
        use_case.execute(DetectStackStringsCommand(address="0x401000"))


def test_single_function_mode_sparse_result_is_empty_not_error():
    decoder = _FakeDecodeGateway({0x401000: []})  # no decodable instructions
    functions = _FakeFunctionRepository([_func(0x401000, "stub")])
    database = _FakeDatabaseGateway()
    use_case = _use_case(decoder, functions, database)

    result = use_case.execute(DetectStackStringsCommand(address="0x401000"))

    assert result.matches == ()
    assert result.truncated is False


def test_single_function_mode_caps_matches_at_the_ceiling():
    # A function that yields more than the ceiling is truncated to it.
    over = MAX_STACK_STRINGS + 1
    # One 4-byte store per distinct "ABCD" run, each on its own gapped slot.
    insns = [_store(0x401000 + i, i * 8, 0x44434241, size=4) for i in range(over)]
    decoder = _FakeDecodeGateway({0x401000: insns})
    functions = _FakeFunctionRepository([_func(0x401000, "big", size=over * 8)])
    database = _FakeDatabaseGateway()
    use_case = _use_case(decoder, functions, database)

    result = use_case.execute(DetectStackStringsCommand(address="0x401000"))

    assert len(result.matches) == MAX_STACK_STRINGS
    assert result.truncated is True


def test_whole_database_sweep_aggregates_across_functions():
    decoder = _FakeDecodeGateway(
        {
            0x401000: _char_run(0x401000, 0, "PASS"),
            0x402000: _char_run(0x402000, 0, "USER"),
        }
    )
    functions = _FakeFunctionRepository(
        [_func(0x401000, "a"), _func(0x402000, "b")]
    )
    database = _FakeDatabaseGateway()
    use_case = _use_case(decoder, functions, database)

    result = use_case.execute(DetectStackStringsCommand())

    assert sorted(m.value for m in result.matches) == ["PASS", "USER"]
    assert result.truncated is False
    assert sorted(decoder.calls) == [0x401000, 0x402000]


def test_whole_database_sweep_skips_functions_that_fail_to_decode():
    # The middle function raises; the sweep continues rather than aborting.
    decoder = _FakeDecodeGateway(
        {
            0x401000: _char_run(0x401000, 0, "PASS"),
            0x403000: _char_run(0x403000, 0, "USER"),
        },
        fail=frozenset({0x402000}),
    )
    functions = _FakeFunctionRepository(
        [_func(0x401000, "a"), _func(0x402000, "bad"), _func(0x403000, "c")]
    )
    database = _FakeDatabaseGateway()
    use_case = _use_case(decoder, functions, database)

    result = use_case.execute(DetectStackStringsCommand())

    assert sorted(m.value for m in result.matches) == ["PASS", "USER"]
    assert result.truncated is False


def test_whole_database_sweep_walks_multiple_pages():
    decoder = _FakeDecodeGateway(
        {
            0x401000: _char_run(0x401000, 0, "AAAA"),
            0x402000: _char_run(0x402000, 0, "BBBB"),
            0x403000: _char_run(0x403000, 0, "CCCC"),
        }
    )
    functions = _FakeFunctionRepository(
        [_func(0x401000, "a"), _func(0x402000, "b"), _func(0x403000, "c")],
        page_size=1,  # force one function per page
    )
    database = _FakeDatabaseGateway()
    use_case = _use_case(decoder, functions, database)

    result = use_case.execute(DetectStackStringsCommand())

    assert sorted(m.value for m in result.matches) == ["AAAA", "BBBB", "CCCC"]
    assert len(decoder.calls) == 3


def test_whole_database_sweep_empty_database_is_not_truncated():
    decoder = _FakeDecodeGateway({})
    functions = _FakeFunctionRepository([])
    database = _FakeDatabaseGateway()
    use_case = _use_case(decoder, functions, database)

    result = use_case.execute(DetectStackStringsCommand())

    assert result.matches == ()
    assert result.truncated is False
    assert decoder.calls == []


def test_whole_database_sweep_bounds_the_function_count():
    # More functions than the scan bound: the sweep stops and flags truncation.
    over = MAX_SCAN_FUNCTIONS + 1
    funcs = [_func(0x400000 + i * 0x100, f"f{i}") for i in range(over)]
    decoder = _FakeDecodeGateway({f.ea.value: [] for f in funcs})
    functions = _FakeFunctionRepository(funcs)
    database = _FakeDatabaseGateway()
    use_case = _use_case(decoder, functions, database)

    result = use_case.execute(DetectStackStringsCommand())

    assert result.truncated is True
    # No more than the bound was decoded.
    assert len(decoder.calls) == MAX_SCAN_FUNCTIONS


# ==========================================================================
# view projection
# ==========================================================================


def test_stack_string_view_projects_flat_shape():
    view = stack_string_view(
        StackString(address=Address(0x14000A), value="PASS", function="decrypt")
    )
    assert view == {"address": "0x14000a", "value": "PASS", "function": "decrypt"}


def test_stack_string_view_carries_a_missing_function_as_none():
    view = stack_string_view(StackString(address=Address(0x1000), value="PASS"))
    assert view == {"address": "0x1000", "value": "PASS", "function": None}


def test_detect_stack_strings_view_projects_result_to_wire_shape():
    result = DetectStackStringsResult(
        matches=(
            StackString(address=Address(0x401000), value="PASS", function="a"),
            StackString(address=Address(0x402000), value="USER", function="b"),
        ),
        truncated=True,
    )

    view = detect_stack_strings_view(result)

    assert view["matches"] == [
        {"address": "0x401000", "value": "PASS", "function": "a"},
        {"address": "0x402000", "value": "USER", "function": "b"},
    ]
    assert view["truncated"] is True


def test_detect_stack_strings_view_projects_empty_result():
    view = detect_stack_strings_view(
        DetectStackStringsResult(matches=(), truncated=False)
    )
    assert view == {"matches": [], "truncated": False}


# ==========================================================================
# catalog registration
# ==========================================================================


def _register(use_case: DetectStackStringsUseCase, executor: _InlineExecutor) -> Registry:
    registry = Registry()
    register_detect_stack_strings(
        registry,
        detect_stack_strings_use_case=use_case,
        executor=executor,
    )
    return registry


def test_detect_stack_strings_is_registered_read_only():
    decoder = _FakeDecodeGateway({})
    use_case = _use_case(decoder, _FakeFunctionRepository([]), _FakeDatabaseGateway())
    registry = _register(use_case, _InlineExecutor())

    spec = registry.get_tool("detect_stack_strings")
    assert spec is not None
    # A pure decoded-instruction scan mutates nothing.
    assert spec.annotations["readOnlyHint"] is True
    assert "destructiveHint" not in spec.annotations


def test_detect_stack_strings_tool_invocation_returns_wire_shape():
    decoder = _FakeDecodeGateway({0x401000: _char_run(0x401000, 0, "PASS")})
    functions = _FakeFunctionRepository([_func(0x401000, "decrypt")])
    executor = _InlineExecutor()
    registry = _register(_use_case(decoder, functions, _FakeDatabaseGateway()), executor)

    view = registry.get_tool("detect_stack_strings").invoke(address="0x401000")

    assert view == {
        "matches": [
            {"address": "0x401000", "value": "PASS", "function": "decrypt"}
        ],
        "truncated": False,
    }
    # The scan ran through the executor exactly once, without write affinity.
    assert executor.write_flags == [False]
