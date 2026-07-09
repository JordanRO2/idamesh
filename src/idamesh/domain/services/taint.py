"""The taint service — pure, IDA-free, bounded intra-procedural source→sink taint.

:class:`TaintService` composes :class:`~idamesh.domain.services.data_flow.DataFlowService`
(for propagation) and :class:`~idamesh.domain.services.dangerous_apis.DangerousApiService`
(for the sink set) to answer a single, bounded question within one function: does
data produced by an *input source* reach the argument of a *dangerous sink*?

The approximation, authored here:

* **Source.** A call to an input-producing API (``recv`` / ``read`` / ``fgets`` /
  ``ReadFile`` …) taints its return value (``rax``). The source list is our
  authored vocabulary.
* **Propagation.** The tainted value is followed forward with the pure dataflow
  primitive, tainting copies on ``mov``.
* **Sink.** A later ``call`` to a dangerous API (classified by
  :class:`DangerousApiService`) is reported as a reached sink only when a tainted
  value is actually in one of *that call's* arguments: an argument register, or an
  outgoing stack-argument slot set up for the call — a tainted store to an
  ``[rsp+N]`` slot within the argument window since the previous call. A tainted
  frame-local that merely happens to be live at the call no longer trips the sink.

Everything here is **intra-procedural**, **heuristic**, and **bounded** (per-function
instruction cap, propagation-hop cap, and a ``max_paths`` result cap). It does not
model the ABI precisely nor prove reachability; it flags plausible source→sink flows
for review. Operating over the pure decoded model keeps it unit-testable with no IDA.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Set, Tuple

from idamesh.domain.entities.data_flow import DataFlowStep
from idamesh.domain.entities.decoded_instruction import DecodedInstruction
from idamesh.domain.entities.taint import TaintPath
from idamesh.domain.services.data_flow import (
    DataFlowService,
    Location,
    NOTE_SOURCE,
)
from idamesh.domain.services.dangerous_apis import DangerousApiService

#: Default / maximum number of source→sink paths a single scan reports.
DEFAULT_MAX_PATHS: int = 64
MAX_MAX_PATHS: int = 512

#: Hops the underlying forward propagation may take per source (bounded pass).
_PROPAGATION_STEPS: int = 512

#: The register that holds a call's integer return value (authored, x86-64 fact).
_RETURN_REG: str = "rax"

#: Argument-passing registers across the common x86-64 ABIs (System V + Win64),
#: unioned. A sink call is "reached" when a tainted value lives in one of these.
_ARG_REGS: Tuple[str, ...] = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")

#: Authored input-source APIs whose return value seeds taint. Base names,
#: undecorated; matching tolerates a leading underscore / Win32 A/W suffix.
_INPUT_SOURCES: frozenset = frozenset(
    {
        "recv", "recvfrom", "read", "fread", "fgets", "gets", "getline",
        "scanf", "fscanf", "sscanf", "getenv", "ReadFile", "InternetReadFile",
        "WSARecv", "GetEnvironmentVariable", "fgetc", "getchar", "readlink",
    }
)


class TaintService:
    """Bounded, heuristic intra-procedural source→sink taint over decoded code."""

    def __init__(self, data_flow: Optional[DataFlowService] = None) -> None:
        self._data_flow = data_flow or DataFlowService()

    def trace(
        self,
        instructions: Sequence[DecodedInstruction],
        *,
        danger: DangerousApiService,
        max_paths: int = DEFAULT_MAX_PATHS,
    ) -> Tuple[List[TaintPath], bool]:
        """Return ``(paths, truncated)`` for source→sink flows in ``instructions``.

        Each input-source call in the function seeds taint on its return register;
        the taint is propagated forward, and every later dangerous-API call fed a
        tainted value in one of *its own* arguments (an argument register, or an
        outgoing stack-argument slot set up for that call) yields a
        :class:`TaintPath`. Results are capped at the clamped ``max_paths``;
        ``truncated`` is set when the cap elided further paths. An empty result is
        valid (sparse), not an error.
        """
        cap = self._clamp_paths(max_paths)
        paths: List[TaintPath] = []
        truncated = False

        for index, insn in enumerate(instructions):
            if not self._is_source_call(insn):
                continue
            for path in self._paths_from_source(instructions, index, danger):
                if len(paths) >= cap:
                    truncated = True
                    return paths, truncated
                paths.append(path)
        return paths, truncated

    # -- internals ---------------------------------------------------------

    def _paths_from_source(
        self,
        instructions: Sequence[DecodedInstruction],
        source_index: int,
        danger: DangerousApiService,
    ) -> List[TaintPath]:
        """Propagate from one source call and collect every reached sink path."""
        source = instructions[source_index]
        seed = Location("reg", _RETURN_REG)
        seed_step = DataFlowStep(
            address=source.ea,
            insn=source.text,
            note=NOTE_SOURCE,
            target=self._callee_name(source),
        )
        reached = self._data_flow.forward_reach(
            instructions,
            start_index=source_index,
            seeds=[seed],
            max_steps=_PROPAGATION_STEPS,
        )
        results: List[TaintPath] = []
        steps: List[DataFlowStep] = [seed_step]
        # Tainted-eligible stack slots stored to since the most recent call — the
        # outgoing argument-setup window for the *next* call. Any call (sink or
        # not) closes the window: a slot spilled before an intervening call is not
        # an argument to a later one.
        arg_window: Set[Location] = set()
        for _index, insn, tainted_before in reached:
            if self._callee_name(insn) is not None:
                api = self._sink_api(insn, danger)
                if api is not None and self._reaches_arg(
                    tainted_before, arg_window
                ):
                    results.append(
                        TaintPath(
                            source=source.ea,
                            sink=insn.ea,
                            api=api,
                            steps=tuple(
                                steps
                                + [
                                    DataFlowStep(
                                        address=insn.ea,
                                        insn=insn.text,
                                        note="sink",
                                        target=api,
                                    )
                                ]
                            ),
                        )
                    )
                elif tainted_before:
                    # Taint flows past this (non-reaching / benign) call.
                    steps.append(
                        DataFlowStep(
                            address=insn.ea,
                            insn=insn.text,
                            note="flow",
                            target=None,
                        )
                    )
                arg_window = set()
                continue
            # A non-call instruction: a store to a stack slot sets up a candidate
            # outgoing argument for the pending call; record it for the window.
            self._record_stack_writes(insn, arg_window)
            if tainted_before:
                steps.append(
                    DataFlowStep(
                        address=insn.ea,
                        insn=insn.text,
                        note="flow",
                        target=None,
                    )
                )
        return results

    def _reaches_arg(
        self,
        tainted: "frozenset[Location]",
        arg_window: "Set[Location]",
    ) -> bool:
        """``True`` when a tainted value is in an argument *of this call*.

        A tainted argument register reaches the sink. A tainted stack slot counts
        only when it is an outgoing argument of *this* call: stored within the
        argument-setup window since the previous call (in ``arg_window``) and at a
        non-negative stack displacement (an ``[rsp+N]`` outgoing-argument slot, not
        a frame-local spill). A tainted local that is merely live at the call — the
        prior over-broad rule — no longer reaches the sink.
        """
        arg_locs: Set[Location] = {Location("reg", reg) for reg in _ARG_REGS}
        if tainted & arg_locs:
            return True
        return any(
            loc.kind == "stack"
            and loc in arg_window
            and self._is_outgoing_arg_slot(loc)
            for loc in tainted
        )

    @staticmethod
    def _record_stack_writes(
        insn: DecodedInstruction, arg_window: "Set[Location]"
    ) -> None:
        """Add any stack slot this instruction writes to the argument window."""
        for op in insn.operands:
            if not op.is_write:
                continue
            slot = op.stack_slot()
            if slot is not None:
                arg_window.add(Location("stack", str(slot)))

    @staticmethod
    def _is_outgoing_arg_slot(loc: Location) -> bool:
        """``True`` for a non-negative stack displacement (an ``[rsp+N]`` arg slot).

        Outgoing stack arguments live at non-negative offsets from the stack
        pointer; a negative displacement is a frame-local, never an argument.
        """
        try:
            return int(loc.key) >= 0
        except ValueError:
            return False

    def _is_source_call(self, insn: DecodedInstruction) -> bool:
        """``True`` when the instruction is a call to an input-source API."""
        name = self._callee_name(insn)
        if name is None:
            return False
        return self._base_name(name) in _INPUT_SOURCES

    def _sink_api(
        self, insn: DecodedInstruction, danger: DangerousApiService
    ) -> Optional[str]:
        """Canonical dangerous-API name when the instruction calls a sink."""
        name = self._callee_name(insn)
        if name is None:
            return None
        classified = danger.classify(name)
        return classified.name if classified is not None else None

    @staticmethod
    def _callee_name(insn: DecodedInstruction) -> Optional[str]:
        """Extract the callee symbol from a ``call`` instruction, else ``None``."""
        if insn.mnemonic.strip().lower() != "call":
            return None
        target = insn.operand(0)
        if target is None:
            return None
        text = target.text.strip()
        return text or None

    @staticmethod
    def _base_name(name: str) -> str:
        """Undecorate a callee name to its base form (drop ``_`` / trailing A/W)."""
        stripped = name.lstrip("_")
        if len(stripped) > 1 and stripped[-1] in ("A", "W"):
            core = stripped[:-1]
            if core in _INPUT_SOURCES:
                return core
        return stripped

    @staticmethod
    def _clamp_paths(max_paths: int) -> int:
        """Clamp a requested path budget into ``[0, MAX_MAX_PATHS]``."""
        if max_paths <= 0:
            return 0
        return min(max_paths, MAX_MAX_PATHS)
