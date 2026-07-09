"""Unit tests for ``trace_data_flow`` — bounded intra-procedural def-use (no IDA).

Every layer is exercised entirely off-host over *synthetic* decoded instructions,
so the pure algorithm is proven without a disassembler present:

* the pure :class:`DataFlowService` — forward use-chains, ``mov``/``lea``
  propagation, in-place transforms, the redefinition that kills a tracked value,
  backward def-chains that hop to a copy's source, register-family aliasing,
  stack-slot identity, the step budget / truncation flag, and the
  :meth:`~DataFlowService.forward_reach` primitive the taint tracer composes;
* the :class:`Location` value object B owns and C consumes — its derivation from
  an operand and its rendering;
* the :class:`TraceDataFlowUseCase` — driven by fake decode / function / database
  gateways so anchor resolution, function decoding, and the empty/error paths are
  asserted with no database; and
* the catalog projection and read-only registration — the flat ``0x``-hex wire
  shape and the tool wiring.

The value the tracker follows is a *location*: a canonical register family
(``eax``/``al`` fold to ``rax``) or a stack slot keyed by displacement. A walk is
a single bounded linear pass, heuristic by design; these tests pin that behaviour.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Sequence, Tuple, TypeVar

import pytest

from idamesh.application.contexts.trace_data_flow import TraceDataFlowUseCase
from idamesh.application.dto.trace_data_flow import (
    DEFAULT_MAX_STEPS as DTO_DEFAULT_MAX_STEPS,
    MAX_MAX_STEPS as DTO_MAX_MAX_STEPS,
    TraceDataFlowCommand,
    TraceDataFlowResult,
)
from idamesh.domain.entities.data_flow import DataFlowStep
from idamesh.domain.entities.decoded_instruction import (
    DecodedInstruction,
    Operand,
    OPERAND_KIND_IMM,
    OPERAND_KIND_MEM,
    OPERAND_KIND_PHRASE,
    OPERAND_KIND_REG,
)
from idamesh.domain.entities.function import Function
from idamesh.domain.services.data_flow import (
    DEFAULT_MAX_STEPS,
    DIRECTION_BACKWARD,
    DIRECTION_FORWARD,
    MAX_MAX_STEPS,
    NOTE_DEF,
    NOTE_PROPAGATE,
    NOTE_REDEFINED,
    NOTE_TRANSFORM,
    NOTE_USE,
    DataFlowService,
    Location,
)
from idamesh.domain.values.address import Address, Selector
from idamesh.interface.catalog.trace_data_flow import (
    data_flow_step_view,
    register_trace_data_flow,
    trace_data_flow_view,
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
    """An immediate operand — a read that names no trackable location."""
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


def _stack(
    index: int,
    disp: int,
    *,
    base: str = "rbp",
    read: bool = False,
    write: bool = False,
    idx_reg: Optional[str] = None,
) -> Operand:
    """A ``[base±disp]`` phrase — a simple stack slot unless an index reg is given."""
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
    return DecodedInstruction(ea=Address(ea), mnemonic=mnemonic, operands=tuple(operands))


def _trace_tuples(steps: Sequence[DataFlowStep]) -> List[Tuple[int, str, Optional[str]]]:
    """Reduce steps to ``(address, note, target)`` triples for compact assertions."""
    return [(s.address.value, s.note, s.target) for s in steps]


# -- fakes for the use-case -------------------------------------------------


class _FakeDecoder:
    """An ``InstructionDecodeGateway`` returning a fixed instruction list.

    Records the entry address every ``decode_function`` call was made with, so the
    use-case is shown to decode the *containing function*, not the raw anchor.
    """

    def __init__(self, instructions: Sequence[DecodedInstruction]) -> None:
        self._instructions = list(instructions)
        self.decoded_for: List[int] = []

    def decode_function(self, ea: Address) -> List[DecodedInstruction]:
        self.decoded_for.append(ea.value)
        return list(self._instructions)


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
    """A ``DatabaseGateway`` that resolves hex/decimal directly and symbols by map."""

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


# ==========================================================================
# Location — the value B owns and C consumes
# ==========================================================================


def test_location_of_register_folds_to_the_canonical_family():
    # A 32-bit / 8-bit sub-register write aliases the full 64-bit register.
    assert Location.of(_reg(0, "eax", write=True)) == Location("reg", "rax")
    assert Location.of(_reg(1, "al", read=True)) == Location("reg", "rax")
    assert Location.of(_reg(0, "r9d", write=True)) == Location("reg", "r9")


def test_location_of_stack_slot_keys_on_displacement():
    loc = Location.of(_stack(0, -8, write=True))
    assert loc == Location("stack", "-8")
    assert loc.render() == "stack:-8"


def test_location_of_global_mem_keys_on_absolute_address():
    assert Location.of(_mem(0, 0x140A0, read=True)) == Location("mem", "0x140a0")


def test_location_of_immediate_and_indexed_slot_is_none():
    assert Location.of(_imm(1, 0x1234)) is None
    # An indexed access is not treated as a scalar stack slot.
    assert Location.of(_stack(0, -8, idx_reg="rcx", read=True)) is None


def test_location_render_is_kind_colon_key():
    assert Location("reg", "rax").render() == "reg:rax"


# ==========================================================================
# DataFlowService.trace — forward
# ==========================================================================


def test_forward_use_propagate_redefine_chain():
    # mov rax,5 ; add rbx,rax ; mov rcx,rax ; mov rax,9 ; mov rdx,rcx
    # Seed rax at the anchor; follow its uses, its copy into rcx, the redefinition
    # that kills rax, and the surviving copy flowing on into rdx.
    instrs = [
        _insn(0x1000, "mov", _reg(0, "rax", write=True), _imm(1, 5)),
        _insn(0x1004, "add", _reg(0, "rbx", read=True, write=True), _reg(1, "rax", read=True)),
        _insn(0x1008, "mov", _reg(0, "rcx", write=True), _reg(1, "rax", read=True)),
        _insn(0x100C, "mov", _reg(0, "rax", write=True), _imm(1, 9)),
        _insn(0x1010, "mov", _reg(0, "rdx", write=True), _reg(1, "rcx", read=True)),
    ]

    steps, truncated = DataFlowService().trace(instrs, start=0x1000, operand=0)

    assert truncated is False
    assert _trace_tuples(steps) == [
        (0x1004, NOTE_USE, None),
        (0x1008, NOTE_PROPAGATE, "reg:rcx"),
        (0x100C, NOTE_REDEFINED, "reg:rax"),
        (0x1010, NOTE_PROPAGATE, "reg:rdx"),
    ]
    # The anchor instruction itself is never emitted; the first hop reads the
    # instruction text through unchanged.
    assert steps[0].insn == "add rbx, rax"


def test_forward_redefinition_stops_the_trace():
    # mov rax,1 ; mov rax,2 ; mov rbx,rax
    # The second write is not a use of rax: it redefines (kills) it, leaving nothing
    # tracked, so the later read of the *new* rax is not reported.
    instrs = [
        _insn(0x2000, "mov", _reg(0, "rax", write=True), _imm(1, 1)),
        _insn(0x2004, "mov", _reg(0, "rax", write=True), _imm(1, 2)),
        _insn(0x2008, "mov", _reg(0, "rbx", write=True), _reg(1, "rax", read=True)),
    ]

    steps, truncated = DataFlowService().trace(instrs, start=0x2000, operand=0)

    assert truncated is False
    assert _trace_tuples(steps) == [(0x2004, NOTE_REDEFINED, "reg:rax")]


def test_forward_mov_propagation_names_the_destination():
    instrs = [
        _insn(0x3000, "mov", _reg(0, "rax", write=True), _imm(1, 7)),
        _insn(0x3004, "mov", _reg(0, "rbx", write=True), _reg(1, "rax", read=True)),
    ]

    steps, _ = DataFlowService().trace(instrs, start=0x3000, operand=0)

    assert _trace_tuples(steps) == [(0x3004, NOTE_PROPAGATE, "reg:rbx")]


def test_forward_lea_address_arithmetic_propagates():
    # lea reads the base register during address computation, so a tracked base
    # flows into the lea destination.
    instrs = [
        _insn(0x3100, "mov", _reg(0, "rax", write=True), _reg(1, "rdi", read=True)),
        _insn(0x3104, "lea", _reg(0, "rbx", write=True), _stack(1, 8, base="rax", read=True)),
    ]

    steps, _ = DataFlowService().trace(instrs, start=0x3100, operand=0)

    assert _trace_tuples(steps) == [(0x3104, NOTE_PROPAGATE, "reg:rbx")]


def test_forward_in_place_transform_keeps_tracking():
    # add rax,rbx transforms rax in place: reported as a transform, and rax keeps
    # being followed into the next use.
    instrs = [
        _insn(0xC000, "mov", _reg(0, "rax", write=True), _imm(1, 5)),
        _insn(0xC004, "add", _reg(0, "rax", read=True, write=True), _reg(1, "rbx", read=True)),
        _insn(0xC008, "mov", _reg(0, "rcx", write=True), _reg(1, "rax", read=True)),
    ]

    steps, _ = DataFlowService().trace(instrs, start=0xC000, operand=0)

    assert _trace_tuples(steps) == [
        (0xC004, NOTE_TRANSFORM, None),
        (0xC008, NOTE_PROPAGATE, "reg:rcx"),
    ]


def test_forward_tracks_a_stack_slot_by_displacement():
    # mov [rbp-8],rax ; mov rcx,[rbp-8]  — seed the slot, follow it into rcx.
    instrs = [
        _insn(0x4000, "mov", _stack(0, -8, write=True), _reg(1, "rax", read=True)),
        _insn(0x4004, "mov", _reg(0, "rcx", write=True), _stack(1, -8, read=True)),
    ]

    steps, _ = DataFlowService().trace(instrs, start=0x4000, operand=0)

    assert _trace_tuples(steps) == [(0x4004, NOTE_PROPAGATE, "reg:rcx")]


def test_forward_register_aliasing_uses_the_family():
    # Seed the full register rax; a later read of the 8-bit alias al counts as a use.
    instrs = [
        _insn(0x5000, "mov", _reg(0, "rax", write=True), _imm(1, 5)),
        _insn(0x5004, "xor", _reg(0, "cl", read=True, write=True), _reg(1, "al", read=True)),
    ]

    steps, _ = DataFlowService().trace(instrs, start=0x5000, operand=0)

    assert _trace_tuples(steps) == [(0x5004, NOTE_USE, None)]


# ==========================================================================
# DataFlowService.trace — backward
# ==========================================================================


def test_backward_finds_the_defining_write_immediate_source_unfollowable():
    # Trace rax backward from the mov that reads it; the defining write loads an
    # immediate, so the def is recorded but cannot be followed further.
    instrs = [
        _insn(0x6000, "mov", _reg(0, "rax", write=True), _imm(1, 3)),
        _insn(0x6004, "add", _reg(0, "rbx", read=True, write=True), _reg(1, "rcx", read=True)),
        _insn(0x6008, "mov", _reg(0, "rdx", write=True), _reg(1, "rax", read=True)),
    ]

    steps, truncated = DataFlowService().trace(
        instrs, start=0x6008, operand=1, direction=DIRECTION_BACKWARD
    )

    assert truncated is False
    # The intervening add(rbx,rcx) does not define rax, so it is skipped.
    assert _trace_tuples(steps) == [(0x6000, NOTE_DEF, None)]


def test_backward_hops_through_a_copy_chain_to_the_root_source():
    # rdi := [rbp-16] ; rsi := rdi ; rax := rsi.  Tracing rsi backward hops rsi→rdi
    # then rdi→stack:-16, following each copy to its source location.
    instrs = [
        _insn(0x7000, "mov", _reg(0, "rdi", write=True), _stack(1, -16, read=True)),
        _insn(0x7004, "mov", _reg(0, "rsi", write=True), _reg(1, "rdi", read=True)),
        _insn(0x7008, "mov", _reg(0, "rax", write=True), _reg(1, "rsi", read=True)),
    ]

    steps, truncated = DataFlowService().trace(
        instrs, start=0x7008, operand=1, direction=DIRECTION_BACKWARD
    )

    assert truncated is False
    assert _trace_tuples(steps) == [
        (0x7004, NOTE_DEF, "reg:rdi"),
        (0x7000, NOTE_DEF, "stack:-16"),
    ]


# ==========================================================================
# DataFlowService.trace — bounds & degenerate inputs
# ==========================================================================


def test_step_cap_truncates_with_work_remaining():
    instrs = [
        _insn(0x8000, "mov", _reg(0, "rax", write=True), _imm(1, 1)),
        _insn(0x8004, "add", _reg(0, "rbx", read=True, write=True), _reg(1, "rax", read=True)),
        _insn(0x8008, "add", _reg(0, "rcx", read=True, write=True), _reg(1, "rax", read=True)),
        _insn(0x800C, "add", _reg(0, "rdx", read=True, write=True), _reg(1, "rax", read=True)),
    ]

    steps, truncated = DataFlowService().trace(instrs, start=0x8000, operand=0, max_steps=2)

    assert len(steps) == 2
    assert truncated is True
    assert [s.address.value for s in steps] == [0x8004, 0x8008]


def test_full_trace_within_budget_is_not_truncated():
    instrs = [
        _insn(0x8100, "mov", _reg(0, "rax", write=True), _imm(1, 1)),
        _insn(0x8104, "add", _reg(0, "rbx", read=True, write=True), _reg(1, "rax", read=True)),
    ]

    steps, truncated = DataFlowService().trace(instrs, start=0x8100, operand=0, max_steps=64)

    assert len(steps) == 1
    assert truncated is False


def test_max_steps_is_clamped_to_the_ceiling():
    # An absurd budget does not overflow the walk; a short listing still terminates.
    instrs = [
        _insn(0x8200, "mov", _reg(0, "rax", write=True), _imm(1, 1)),
        _insn(0x8204, "add", _reg(0, "rbx", read=True, write=True), _reg(1, "rax", read=True)),
    ]

    steps, truncated = DataFlowService().trace(
        instrs, start=0x8200, operand=0, max_steps=MAX_MAX_STEPS * 100
    )

    assert len(steps) == 1
    assert truncated is False


def test_immediate_operand_seed_yields_empty_trace():
    instrs = [_insn(0x9000, "mov", _reg(0, "rax", write=True), _imm(1, 5))]

    steps, truncated = DataFlowService().trace(instrs, start=0x9000, operand=1)

    assert steps == []
    assert truncated is False


def test_anchor_address_not_found_yields_empty_trace():
    instrs = [_insn(0x9000, "mov", _reg(0, "rax", write=True), _imm(1, 5))]

    steps, truncated = DataFlowService().trace(instrs, start=0xDEAD, operand=0)

    assert steps == []
    assert truncated is False


def test_empty_instruction_list_is_a_valid_empty_result():
    steps, truncated = DataFlowService().trace([], start=0x1000, operand=0)
    assert steps == []
    assert truncated is False


# ==========================================================================
# DataFlowService.forward_reach — the taint primitive C composes
# ==========================================================================


def test_forward_reach_reports_tainted_set_before_each_instruction():
    # Seed rdi; the copy into rsi then the store to a stack slot both propagate the
    # taint. Each yielded set is the taint live *as the instruction executes*.
    instrs = [
        _insn(0xA000, "call", _reg(0, "rax", write=True)),
        _insn(0xA004, "mov", _reg(0, "rsi", write=True), _reg(1, "rdi", read=True)),
        _insn(0xA008, "mov", _stack(0, -8, write=True), _reg(1, "rsi", read=True)),
    ]

    reached = DataFlowService().forward_reach(
        instrs, start_index=0, seeds=[Location("reg", "rdi")]
    )

    indices = [idx for idx, _insn_, _t in reached]
    tainted_before = [set(t) for _idx, _insn_, t in reached]
    assert indices == [1, 2]
    assert tainted_before[0] == {Location("reg", "rdi")}
    # By the store, rsi has picked up the taint from the copy.
    assert Location("reg", "rsi") in tainted_before[1]


def test_forward_reach_is_bounded_by_max_steps():
    instrs = [
        _insn(0xB000, "nop"),
        _insn(0xB004, "add", _reg(0, "rbx", read=True, write=True), _reg(1, "rdi", read=True)),
        _insn(0xB008, "add", _reg(0, "rcx", read=True, write=True), _reg(1, "rdi", read=True)),
        _insn(0xB00C, "add", _reg(0, "rdx", read=True, write=True), _reg(1, "rdi", read=True)),
    ]

    reached = DataFlowService().forward_reach(
        instrs, start_index=0, seeds=[Location("reg", "rdi")], max_steps=2
    )

    assert [idx for idx, _i, _t in reached] == [1, 2]


def test_forward_reach_halts_when_taint_is_cleared():
    # rdi is overwritten by a taint-free source, so propagation stops immediately.
    instrs = [
        _insn(0xB100, "nop"),
        _insn(0xB104, "mov", _reg(0, "rdi", write=True), _imm(1, 0)),
        _insn(0xB108, "mov", _reg(0, "rsi", write=True), _reg(1, "rdi", read=True)),
    ]

    reached = DataFlowService().forward_reach(
        instrs, start_index=0, seeds=[Location("reg", "rdi")]
    )

    # Only the clearing instruction is examined; once taint is empty the walk ends.
    assert [idx for idx, _i, _t in reached] == [1]


# ==========================================================================
# TraceDataFlowUseCase — resolution, decoding, wiring
# ==========================================================================


def _use_case(
    instrs: Sequence[DecodedInstruction],
    *,
    func: Optional[Function],
    symbols: Optional[dict] = None,
) -> Tuple[TraceDataFlowUseCase, _FakeDecoder]:
    decoder = _FakeDecoder(instrs)
    use_case = TraceDataFlowUseCase(
        decoder,
        DataFlowService(),
        _FakeFunctions(func),
        _FakeDatabase(symbols),
    )
    return use_case, decoder


def _sample_function() -> Function:
    return Function(ea=Address(0x1000), name="sub_1000", size=0x20)


def _sample_instructions() -> List[DecodedInstruction]:
    return [
        _insn(0x1000, "mov", _reg(0, "rax", write=True), _imm(1, 5)),
        _insn(0x1004, "mov", _reg(0, "rbx", write=True), _reg(1, "rax", read=True)),
    ]


def test_use_case_resolves_anchor_and_decodes_the_containing_function():
    use_case, decoder = _use_case(_sample_instructions(), func=_sample_function())

    result = use_case.execute(TraceDataFlowCommand(address="0x1000", operand=0))

    assert isinstance(result, TraceDataFlowResult)
    assert result.start == "0x1000"
    assert result.direction == "forward"
    assert result.truncated is False
    assert _trace_tuples(result.steps) == [(0x1004, NOTE_PROPAGATE, "reg:rbx")]
    # The function entry (0x1000) is decoded, not the raw anchor selector.
    assert decoder.decoded_for == [0x1000]


def test_use_case_anchor_may_sit_past_the_function_entry():
    # Anchor at the second instruction; the tracer starts from there.
    use_case, _ = _use_case(_sample_instructions(), func=_sample_function())

    result = use_case.execute(TraceDataFlowCommand(address="0x1004", operand=0))

    assert result.start == "0x1004"
    # rbx is defined here and never used again → an empty (valid) forward trace.
    assert result.steps == ()
    assert result.truncated is False


def test_use_case_backward_direction_is_passed_through():
    use_case, _ = _use_case(_sample_instructions(), func=_sample_function())

    result = use_case.execute(
        TraceDataFlowCommand(address="0x1004", operand=1, direction=DIRECTION_BACKWARD)
    )

    assert result.direction == DIRECTION_BACKWARD
    # rbx := rax, so tracing rax's source backward finds the immediate def of rax.
    assert _trace_tuples(result.steps) == [(0x1000, NOTE_DEF, None)]


def test_use_case_resolves_a_symbol_selector():
    use_case, decoder = _use_case(
        _sample_instructions(), func=_sample_function(), symbols={"start": 0x1000}
    )

    result = use_case.execute(TraceDataFlowCommand(address="start", operand=0))

    assert result.start == "0x1000"
    assert decoder.decoded_for == [0x1000]


def test_use_case_address_in_no_function_raises():
    use_case, _ = _use_case(_sample_instructions(), func=None)

    with pytest.raises(ValueError):
        use_case.execute(TraceDataFlowCommand(address="0x1000"))


def test_use_case_clamps_oversized_max_steps():
    # A huge request must not reach the service unclamped; the trace still completes.
    use_case, _ = _use_case(_sample_instructions(), func=_sample_function())

    result = use_case.execute(
        TraceDataFlowCommand(address="0x1000", operand=0, max_steps=DTO_MAX_MAX_STEPS * 1000)
    )

    assert result.truncated is False
    assert len(result.steps) == 1


def test_dto_caps_match_the_service():
    assert DTO_DEFAULT_MAX_STEPS == DEFAULT_MAX_STEPS
    assert DTO_MAX_MAX_STEPS == MAX_MAX_STEPS


# ==========================================================================
# View projection
# ==========================================================================


def test_data_flow_step_view_projects_flat_hex_shape():
    view = data_flow_step_view(
        DataFlowStep(address=Address(0x14000A), insn="mov rbx, rax", note=NOTE_PROPAGATE, target="reg:rbx")
    )
    assert view == {
        "address": "0x14000a",
        "insn": "mov rbx, rax",
        "note": "propagate",
        "target": "reg:rbx",
    }


def test_trace_data_flow_view_projects_result_to_wire_shape():
    result = TraceDataFlowResult(
        start="0x1000",
        direction="forward",
        steps=(
            DataFlowStep(address=Address(0x1004), insn="add rbx, rax", note=NOTE_USE, target=None),
            DataFlowStep(address=Address(0x1008), insn="mov rcx, rax", note=NOTE_PROPAGATE, target="reg:rcx"),
        ),
        truncated=True,
    )

    view = trace_data_flow_view(result)

    assert view == {
        "start": "0x1000",
        "direction": "forward",
        "steps": [
            {"address": "0x1004", "insn": "add rbx, rax", "note": "use", "target": None},
            {"address": "0x1008", "insn": "mov rcx, rax", "note": "propagate", "target": "reg:rcx"},
        ],
        "truncated": True,
    }


def test_trace_data_flow_view_projects_empty_result():
    view = trace_data_flow_view(
        TraceDataFlowResult(start="0x1000", direction="backward", steps=(), truncated=False)
    )
    assert view == {
        "start": "0x1000",
        "direction": "backward",
        "steps": [],
        "truncated": False,
    }


# ==========================================================================
# Catalog registration
# ==========================================================================


def _register(instrs, func, executor) -> Registry:
    registry = Registry()
    use_case = TraceDataFlowUseCase(
        _FakeDecoder(instrs), DataFlowService(), _FakeFunctions(func), _FakeDatabase()
    )
    register_trace_data_flow(
        registry, trace_data_flow_use_case=use_case, executor=executor
    )
    return registry


def test_trace_data_flow_is_registered_read_only():
    registry = _register(_sample_instructions(), _sample_function(), _InlineExecutor())

    spec = registry.get_tool("trace_data_flow")
    assert spec is not None
    # An intra-procedural def-use walk mutates nothing.
    assert spec.annotations["readOnlyHint"] is True


def test_registered_tool_invocation_returns_the_wire_shape():
    executor = _InlineExecutor()
    registry = _register(_sample_instructions(), _sample_function(), executor)

    spec = registry.get_tool("trace_data_flow")
    out = spec.invoke(address="0x1000", operand=0)

    assert out["start"] == "0x1000"
    assert out["direction"] == "forward"
    assert out["truncated"] is False
    assert out["steps"] == [
        {"address": "0x1004", "insn": "mov rbx, rax", "note": "propagate", "target": "reg:rbx"}
    ]
    # A read-only tool is marshalled onto the kernel thread without write affinity.
    assert executor.write_flags == [False]
