"""Unit tests for ``trace_source_to_sink`` — bounded intra-procedural taint (no IDA).

The whole capability is exercised entirely off-host over the pure decoded-instruction
model, so no disassembler is present:

* the pure :class:`TaintService` — its authored source/sink heuristic (an input-
  producing call taints its return register; a later dangerous-API call fed a
  tainted value in one of *its own* arguments — an argument register, or an
  outgoing stack-argument slot set up for that call — is a reached sink),
  forward propagation through ``mov`` chains, redefinition killing taint, the
  source-name normalization (leading ``_`` / Win32 ``A``/``W``), and the
  ``max_paths`` cap / truncation flag;
* the :class:`TraceSourceToSinkUseCase` — driven by fake decode / function / database
  gateways, so single-function scoping, the bounded whole-database sweep, decode-
  failure tolerance during a sweep, and the "no function contains address" error are
  all asserted with no database; and
* the catalog projection and registration — the nested ``0x``-hex wire shape and the
  read-only tool wiring.

Every finding names the rule that produced it; an empty result is a valid (sparse)
outcome, not an error.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, TypeVar

import pytest

from idamesh.application.contexts.trace_source_to_sink import (
    TraceSourceToSinkUseCase,
)
from idamesh.application.dto.trace_source_to_sink import (
    DEFAULT_MAX_PATHS,
    MAX_MAX_PATHS,
    MAX_SCAN_FUNCTIONS,
    TraceSourceToSinkCommand,
    TraceSourceToSinkResult,
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
from idamesh.domain.entities.taint import TaintPath
from idamesh.domain.services.dangerous_apis import DangerousApiService
from idamesh.domain.services.data_flow import DataFlowService
from idamesh.domain.services.taint import (
    DEFAULT_MAX_PATHS as SERVICE_DEFAULT_MAX_PATHS,
    MAX_MAX_PATHS as SERVICE_MAX_MAX_PATHS,
    TaintService,
)
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import Page, PageRequest
from idamesh.interface.catalog.trace_source_to_sink import (
    register_trace_source_to_sink,
    taint_path_view,
    taint_step_view,
    trace_source_to_sink_view,
)
from idamesh.interface.mcp.registry import Registry

T = TypeVar("T")


# -- synthetic decoded-instruction builders ---------------------------------


def _reg(index: int, name: str, *, read: bool = False, write: bool = False) -> Operand:
    """A register operand (``rax`` …) with the given read/write access flags."""
    return Operand(
        index=index,
        kind=OPERAND_KIND_REG,
        text=name,
        reg=name,
        is_read=read,
        is_write=write,
    )


def _imm(index: int, value: int) -> Operand:
    """An immediate/constant operand (always a read, never a tracked location)."""
    return Operand(
        index=index,
        kind=OPERAND_KIND_IMM,
        text=hex(value),
        value=value,
        is_read=True,
    )


def _slot(
    index: int,
    disp: int,
    *,
    read: bool = False,
    write: bool = False,
    base: str = "rsp",
) -> Operand:
    """A simple ``[stack_reg±disp]`` stack-slot phrase operand."""
    sign = "+" if disp >= 0 else "-"
    return Operand(
        index=index,
        kind=OPERAND_KIND_PHRASE,
        text=f"[{base}{sign}{abs(disp):#x}]",
        base_reg=base,
        disp=disp,
        is_read=read,
        is_write=write,
    )


def _mov(ea: int, dst: Operand, src: Operand) -> DecodedInstruction:
    """A ``mov dst, src`` copy instruction (dst is written, src is read)."""
    return DecodedInstruction(ea=Address(ea), mnemonic="mov", operands=(dst, src))


def _call(ea: int, name: str) -> DecodedInstruction:
    """A ``call <name>`` whose target operand names no tracked scalar location."""
    return DecodedInstruction(
        ea=Address(ea),
        mnemonic="call",
        operands=(Operand(index=0, kind=OPERAND_KIND_MEM, text=name, value=None),),
    )


def _source_to_sink(source: str = "recv", sink: str = "strcpy") -> List[DecodedInstruction]:
    """A minimal ``source → mov rdi, rax → sink`` sequence (rdi is arg register 0)."""
    return [
        _call(0x1000, source),
        _mov(0x1004, _reg(0, "rdi", write=True), _reg(1, "rax", read=True)),
        _call(0x1008, sink),
    ]


_DANGER = DangerousApiService()


def _trace(
    instructions: Sequence[DecodedInstruction], **kwargs
):
    """Run a fresh :class:`TaintService` over ``instructions``."""
    return TaintService().trace(instructions, danger=_DANGER, **kwargs)


# -- service: a source reaching a sink yields a path ------------------------


def test_source_reaching_sink_yields_one_path_naming_source_and_sink():
    paths, truncated = _trace(_source_to_sink("recv", "strcpy"))

    assert truncated is False
    assert len(paths) == 1
    path = paths[0]
    assert path.source == Address(0x1000)
    assert path.sink == Address(0x1008)
    assert path.api == "strcpy"


def test_path_steps_narrate_source_flow_and_sink_in_order():
    (path,), _ = _trace(_source_to_sink("recv", "strcpy"))

    # The narrative opens on the tainting source, threads the propagation hop, and
    # closes on the sink — each step naming the rule that fired.
    notes = [step.note for step in path.steps]
    assert notes == ["source", "flow", "sink"]
    assert path.steps[0].target == "recv"
    assert path.steps[0].address == Address(0x1000)
    assert path.steps[-1].target == "strcpy"
    assert path.steps[-1].address == Address(0x1008)


def test_taint_propagates_through_a_register_move_chain():
    # recv → rax, rax → rbx, rbx → rdi, then rdi feeds the sink.
    instructions = [
        _call(0x2000, "recv"),
        _mov(0x2004, _reg(0, "rbx", write=True), _reg(1, "rax", read=True)),
        _mov(0x2008, _reg(0, "rdi", write=True), _reg(1, "rbx", read=True)),
        _call(0x200C, "system"),
    ]

    paths, _ = _trace(instructions)

    assert len(paths) == 1
    assert paths[0].api == "system"
    assert paths[0].source == Address(0x2000)
    assert paths[0].sink == Address(0x200C)


def test_taint_reaches_sink_through_a_stack_slot():
    # A value spilled to a stack slot and left there still counts as reaching the
    # sink (a stack-passed argument), via the tainted-stack-slot rule.
    instructions = [
        _call(0x3000, "recv"),
        _mov(0x3004, _slot(0, 0x20, write=True), _reg(1, "rax", read=True)),
        _call(0x3008, "sprintf"),
    ]

    paths, _ = _trace(instructions)

    assert len(paths) == 1
    assert paths[0].api == "sprintf"


# -- service: the tightened sink-argument rule ------------------------------


def test_tainted_frame_local_not_passed_to_the_sink_yields_no_path():
    # recv taints rax; it is spilled to a *frame-local* slot ([rbp-0x8]) that is
    # merely live at the sink, not set up as one of its arguments. The tightened
    # rule (only a genuine outgoing argument reaches a sink) no longer counts a
    # stale negative-displacement local, so this is not a finding.
    instructions = [
        _call(0x5000, "recv"),
        _mov(
            0x5004,
            _slot(0, -0x8, write=True, base="rbp"),
            _reg(1, "rax", read=True),
        ),
        _call(0x5008, "strcpy"),
    ]

    paths, truncated = _trace(instructions)

    assert paths == []
    assert truncated is False


def test_tainted_stack_arg_before_an_intervening_call_does_not_reach_a_later_sink():
    # The tainted value is stored to an outgoing-argument slot ([rsp+0x20]), but an
    # intervening benign call closes that argument-setup window. A *later* sink at
    # the same slot is not fed by its own argument setup, so it is not reported —
    # the "argument of *that* call" precision.
    instructions = [
        _call(0x6000, "recv"),
        _mov(0x6004, _slot(0, 0x20, write=True), _reg(1, "rax", read=True)),
        _call(0x6008, "puts"),  # benign intervening call → closes the window
        _call(0x600C, "strcpy"),  # sink: slot 0x20 tainted but not in this window
    ]

    paths, truncated = _trace(instructions)

    assert paths == []
    assert truncated is False


def test_stack_arg_stored_in_this_calls_window_still_reaches_the_sink():
    # Control for the intervening-call test: with no call between the outgoing-arg
    # store and the sink, the slot is an argument of that very call and the path
    # returns — confirming the tightening did not over-prune.
    instructions = [
        _call(0x7000, "recv"),
        _mov(0x7004, _slot(0, 0x20, write=True), _reg(1, "rax", read=True)),
        _call(0x7008, "strcpy"),
    ]

    paths, _ = _trace(instructions)

    assert len(paths) == 1
    assert paths[0].api == "strcpy"


# -- service: a source NOT reaching a sink yields no path -------------------


def test_source_not_reaching_arg_register_yields_no_path():
    # recv taints rax, but rax is never moved into an argument register, so the
    # sink call is not fed tainted data.
    instructions = [
        _call(0x1000, "recv"),
        _call(0x1008, "strcpy"),
    ]

    paths, truncated = _trace(instructions)

    assert paths == []
    assert truncated is False


def test_sink_that_is_not_dangerous_yields_no_path():
    # The call the taint reaches is a benign function, not a dangerous API.
    paths, _ = _trace(_source_to_sink("recv", "my_helper"))
    assert paths == []


def test_dangerous_sink_without_a_source_yields_no_path():
    # A dangerous sink fed a value that no input source ever tainted.
    instructions = [
        _mov(0x1000, _reg(0, "rdi", write=True), _reg(1, "rax", read=True)),
        _call(0x1008, "strcpy"),
    ]

    paths, truncated = _trace(instructions)

    assert paths == []
    assert truncated is False


def test_empty_instruction_stream_is_sparse_not_an_error():
    paths, truncated = _trace([])
    assert paths == []
    assert truncated is False


# -- service: redefinition breaks taint -------------------------------------


def test_redefinition_of_the_argument_register_breaks_the_taint_path():
    # Identical to the positive case, but rdi is overwritten with a constant after
    # it is tainted and before the sink — killing the taint that would have reached
    # the argument.
    instructions = [
        _call(0x1000, "recv"),
        _mov(0x1004, _reg(0, "rdi", write=True), _reg(1, "rax", read=True)),
        _mov(0x1006, _reg(0, "rdi", write=True), _imm(1, 0)),
        _call(0x1008, "strcpy"),
    ]

    paths, _ = _trace(instructions)

    assert paths == []


def test_same_stream_without_the_redefinition_does_reach_the_sink():
    # Control for the redefinition test: drop the killing store and the path returns.
    instructions = [
        _call(0x1000, "recv"),
        _mov(0x1004, _reg(0, "rdi", write=True), _reg(1, "rax", read=True)),
        _call(0x1008, "strcpy"),
    ]

    paths, _ = _trace(instructions)

    assert len(paths) == 1


# -- service: the source vocabulary and its normalization -------------------


@pytest.mark.parametrize(
    "source_name",
    ["recv", "fgets", "ReadFile", "_read", "GetEnvironmentVariableA", "WSARecv"],
)
def test_recognized_input_sources_seed_taint(source_name):
    # Each name resolves to an input source, tolerating a leading underscore or a
    # Win32 A/W charset suffix.
    paths, _ = _trace(_source_to_sink(source_name, "strcpy"))
    assert len(paths) == 1
    assert paths[0].source == Address(0x1000)


@pytest.mark.parametrize("benign_name", ["malloc", "printf_wrapper", "my_alloc"])
def test_non_source_calls_do_not_seed_taint(benign_name):
    # A call that is not an input source never taints its return value, so the sink
    # is not reached even though a copy into rdi occurs.
    paths, _ = _trace(_source_to_sink(benign_name, "strcpy"))
    assert paths == []


# -- service: bounding — the max_paths cap and truncation -------------------


def _two_sink_stream() -> List[DecodedInstruction]:
    """A stream where a single tainted source flows into two distinct sinks."""
    return [
        _call(0x4000, "recv"),
        _mov(0x4004, _reg(0, "rdi", write=True), _reg(1, "rax", read=True)),
        _call(0x4008, "strcpy"),
        _mov(0x400C, _reg(0, "rsi", write=True), _reg(1, "rax", read=True)),
        _call(0x4010, "system"),
    ]


def test_multiple_sinks_are_all_reported_when_the_budget_is_ample():
    paths, truncated = _trace(_two_sink_stream(), max_paths=DEFAULT_MAX_PATHS)

    assert truncated is False
    apis = sorted(p.api for p in paths)
    assert apis == ["strcpy", "system"]


def test_path_cap_truncates_and_bounds_the_result():
    paths, truncated = _trace(_two_sink_stream(), max_paths=1)

    assert len(paths) == 1
    assert truncated is True


def test_zero_budget_with_a_reachable_path_reports_truncation():
    # A clamped-shut budget elides the path that exists, so truncation is flagged.
    paths, truncated = _trace(_source_to_sink("recv", "strcpy"), max_paths=0)

    assert paths == []
    assert truncated is True


def test_zero_budget_with_no_path_is_not_truncated():
    # Nothing to elide → the empty result is honest, not truncated.
    paths, truncated = _trace(_source_to_sink("recv", "my_helper"), max_paths=0)

    assert paths == []
    assert truncated is False


def test_max_paths_is_clamped_to_the_service_ceiling():
    # An oversized budget is accepted (clamped internally) and does not error; the
    # single real path is returned in full.
    paths, truncated = _trace(_source_to_sink(), max_paths=10_000_000)
    assert len(paths) == 1
    assert truncated is False


def test_service_caps_match_the_dto_caps():
    assert SERVICE_DEFAULT_MAX_PATHS == DEFAULT_MAX_PATHS == 64
    assert SERVICE_MAX_MAX_PATHS == MAX_MAX_PATHS == 512
    assert MAX_SCAN_FUNCTIONS == 400


def test_injected_data_flow_service_is_composed():
    # The service composes an injected DataFlowService (the propagation primitive).
    service = TaintService(DataFlowService())
    paths, _ = service.trace(_source_to_sink(), danger=_DANGER)
    assert len(paths) == 1


# -- application fakes ------------------------------------------------------


class _FakeDecoder:
    """An ``InstructionDecodeGateway`` returning planted decoded functions by EA.

    ``mapping`` maps a function entry-EA *value* to its decoded instructions. An EA
    in ``failing`` raises to model a function the adapter cannot decode; an EA with
    no mapping raises a domain error (address in no function). Every decode call is
    recorded so the sweep's decode set can be asserted.
    """

    def __init__(
        self,
        mapping: Dict[int, List[DecodedInstruction]],
        *,
        failing: frozenset = frozenset(),
    ) -> None:
        self._mapping = mapping
        self._failing = failing
        self.decoded: List[int] = []

    def decode_function(self, ea: Address) -> List[DecodedInstruction]:
        self.decoded.append(ea.value)
        if ea.value in self._failing:
            raise RuntimeError(f"cannot decode function at {ea.hex()}")
        if ea.value not in self._mapping:
            raise ValueError(f"no function contains address {ea.hex()}")
        return list(self._mapping[ea.value])


class _FakeFunctions:
    """A ``FunctionRepository`` over an in-memory ordered function list."""

    def __init__(
        self,
        funcs: Sequence[Function],
        *,
        containing: Optional[Dict[int, Function]] = None,
    ) -> None:
        self._funcs = list(funcs)
        self._containing = containing or {}

    def list(self, page: PageRequest) -> Page:
        items = self._funcs[page.offset : page.offset + page.count]
        return Page(
            items=items,
            offset=page.offset,
            count=page.count,
            total=len(self._funcs),
            truncated=False,
        )

    def count(self) -> int:
        return len(self._funcs)

    def get(self, ea: Address) -> Optional[Function]:
        for func in self._funcs:
            if func.ea == ea:
                return func
        return None

    def get_containing(self, ea: Address) -> Optional[Function]:
        return self._containing.get(ea.value)


class _FakeDatabase:
    """A ``DatabaseGateway`` resolving selectors from a planted table."""

    def __init__(self, resolved: Dict[str, int]) -> None:
        self._resolved = resolved

    def resolve(self, selector) -> Address:
        if selector.raw not in self._resolved:
            raise ValueError(f"cannot resolve selector: {selector.raw!r}")
        return Address(self._resolved[selector.raw])

    def resolve_symbol(self, name: str) -> Optional[int]:
        return self._resolved.get(name)

    def metadata(self):  # pragma: no cover - unused by the taint use-case
        raise NotImplementedError

    def is_open(self) -> bool:
        return True


@dataclass
class _InlineExecutor:
    """A ``MainThreadExecutor`` that runs jobs inline, recording write affinity."""

    write_flags: List[bool] = field(default_factory=list)

    def run(self, job: Callable[[], T], *, write: bool = False) -> T:
        self.write_flags.append(write)
        return job()

    def on_kernel_thread(self) -> bool:
        return True


def _func(ea: int, name: str) -> Function:
    return Function(ea=Address(ea), name=name, size=0x40)


# -- use-case: single-function scope ----------------------------------------


def test_use_case_single_function_scope_resolves_decodes_and_traces():
    func = _func(0x1000, "handler")
    decoder = _FakeDecoder({0x1000: _source_to_sink("recv", "strcpy")})
    functions = _FakeFunctions([func], containing={0x1000: func})
    database = _FakeDatabase({"0x1000": 0x1000})
    use_case = TraceSourceToSinkUseCase(
        decoder, TaintService(), functions, database, _DANGER
    )

    result = use_case.execute(TraceSourceToSinkCommand(address="0x1000"))

    assert isinstance(result, TraceSourceToSinkResult)
    assert result.truncated is False
    assert len(result.paths) == 1
    assert result.paths[0].api == "strcpy"
    # Exactly the one containing function was decoded.
    assert decoder.decoded == [0x1000]


def test_use_case_address_in_no_function_is_an_error():
    decoder = _FakeDecoder({})
    functions = _FakeFunctions([], containing={})  # nothing contains the address
    database = _FakeDatabase({"0x9999": 0x9999})
    use_case = TraceSourceToSinkUseCase(
        decoder, TaintService(), functions, database, _DANGER
    )

    with pytest.raises(ValueError):
        use_case.execute(TraceSourceToSinkCommand(address="0x9999"))


# -- use-case: bounded whole-database sweep ---------------------------------


def test_use_case_whole_database_sweep_collects_paths_across_functions():
    hit = _func(0x1000, "reader")
    clean = _func(0x2000, "noop")
    decoder = _FakeDecoder(
        {
            0x1000: _source_to_sink("recv", "system"),
            0x2000: [_call(0x2000, "puts")],  # no source, no sink
        }
    )
    functions = _FakeFunctions([hit, clean])
    database = _FakeDatabase({})
    use_case = TraceSourceToSinkUseCase(
        decoder, TaintService(), functions, database, _DANGER
    )

    result = use_case.execute(TraceSourceToSinkCommand(address=""))

    assert len(result.paths) == 1
    assert result.paths[0].api == "system"
    assert result.paths[0].source == Address(0x1000)
    # Both functions were swept.
    assert set(decoder.decoded) == {0x1000, 0x2000}


def test_use_case_sweep_skips_a_function_that_fails_to_decode():
    good = _func(0x1000, "reader")
    broken = _func(0x2000, "corrupt")
    decoder = _FakeDecoder(
        {0x1000: _source_to_sink("recv", "strcpy")},
        failing=frozenset({0x2000}),
    )
    functions = _FakeFunctions([broken, good])  # broken swept first
    database = _FakeDatabase({})
    use_case = TraceSourceToSinkUseCase(
        decoder, TaintService(), functions, database, _DANGER
    )

    result = use_case.execute(TraceSourceToSinkCommand(address=""))

    # The decode failure was swallowed; the good function's path still landed.
    assert len(result.paths) == 1
    assert result.paths[0].api == "strcpy"
    assert set(decoder.decoded) == {0x1000, 0x2000}


def test_use_case_empty_database_yields_empty_untruncated_result():
    decoder = _FakeDecoder({})
    functions = _FakeFunctions([])
    database = _FakeDatabase({})
    use_case = TraceSourceToSinkUseCase(
        decoder, TaintService(), functions, database, _DANGER
    )

    result = use_case.execute(TraceSourceToSinkCommand(address=""))

    assert result.paths == ()
    assert result.truncated is False


# -- view projection --------------------------------------------------------


def test_taint_step_view_projects_flat_hex_shape():
    step = DataFlowStep(
        address=Address(0x14000A), insn="mov rdi, rax", note="flow", target=None
    )
    assert taint_step_view(step) == {
        "address": "0x14000a",
        "insn": "mov rdi, rax",
        "note": "flow",
        "target": None,
    }


def test_taint_path_view_projects_nested_shape():
    path = TaintPath(
        source=Address(0x1000),
        sink=Address(0x1008),
        api="strcpy",
        steps=(
            DataFlowStep(address=Address(0x1000), insn="call recv", note="source", target="recv"),
            DataFlowStep(address=Address(0x1008), insn="call strcpy", note="sink", target="strcpy"),
        ),
    )

    view = taint_path_view(path)

    assert view == {
        "source": "0x1000",
        "sink": "0x1008",
        "api": "strcpy",
        "steps": [
            {"address": "0x1000", "insn": "call recv", "note": "source", "target": "recv"},
            {"address": "0x1008", "insn": "call strcpy", "note": "sink", "target": "strcpy"},
        ],
    }


def test_trace_source_to_sink_view_projects_result_to_wire_shape():
    result = TraceSourceToSinkResult(
        paths=(
            TaintPath(
                source=Address(0x1000),
                sink=Address(0x1008),
                api="strcpy",
                steps=(
                    DataFlowStep(
                        address=Address(0x1000),
                        insn="call recv",
                        note="source",
                        target="recv",
                    ),
                ),
            ),
        ),
        truncated=True,
    )

    view = trace_source_to_sink_view(result)

    assert view["truncated"] is True
    assert len(view["paths"]) == 1
    assert view["paths"][0]["api"] == "strcpy"
    assert view["paths"][0]["source"] == "0x1000"
    assert view["paths"][0]["steps"][0]["note"] == "source"


def test_trace_source_to_sink_view_projects_empty_result():
    view = trace_source_to_sink_view(TraceSourceToSinkResult(paths=(), truncated=False))
    assert view == {"paths": [], "truncated": False}


# -- catalog registration ---------------------------------------------------


def _register(decoder, functions, database, executor) -> Registry:
    registry = Registry()
    use_case = TraceSourceToSinkUseCase(
        decoder, TaintService(), functions, database, _DANGER
    )
    register_trace_source_to_sink(
        registry,
        trace_source_to_sink_use_case=use_case,
        executor=executor,
    )
    return registry


def test_trace_source_to_sink_is_registered_read_only():
    registry = _register(
        _FakeDecoder({}), _FakeFunctions([]), _FakeDatabase({}), _InlineExecutor()
    )

    spec = registry.get_tool("trace_source_to_sink")
    assert spec is not None
    # A taint scan reads the database and mutates nothing.
    assert spec.annotations["readOnlyHint"] is True
    assert "destructiveHint" not in spec.annotations


def test_trace_source_to_sink_tool_invocation_returns_wire_shape():
    func = _func(0x1000, "handler")
    decoder = _FakeDecoder({0x1000: _source_to_sink("recv", "strcpy")})
    functions = _FakeFunctions([func], containing={0x1000: func})
    database = _FakeDatabase({"0x1000": 0x1000})
    executor = _InlineExecutor()
    registry = _register(decoder, functions, database, executor)

    view = registry.get_tool("trace_source_to_sink").invoke(address="0x1000")

    assert view["truncated"] is False
    assert len(view["paths"]) == 1
    path = view["paths"][0]
    assert path["source"] == "0x1000"
    assert path["sink"] == "0x1008"
    assert path["api"] == "strcpy"
    assert [step["note"] for step in path["steps"]] == ["source", "flow", "sink"]
    # The scan ran through the executor exactly once, read-only.
    assert executor.write_flags == [False]
