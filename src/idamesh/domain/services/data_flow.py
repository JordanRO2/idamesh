"""The dataflow service — pure, IDA-free, bounded intra-procedural def-use.

:class:`DataFlowService` follows the value held at a starting ``(instruction,
operand)`` through a function's decoded instructions, either **forward** (its
subsequent uses, propagations, and the redefinition that kills it) or **backward**
(the writes that defined it, hopping to a source location on a ``mov``). The value
is modelled as a *location* — a register family or a stack slot — and the tracer
maintains the set of locations currently holding a copy of it, propagating on
``mov`` and keeping the value across in-place arithmetic transforms.

Every walk is **bounded** (``max_steps`` hops and an instruction ceiling) and
**heuristic**: it is a single linear pass over the listing, not a full CFG
fixpoint, so it approximates rather than proves reachability. Each emitted step
names the rule that fired. The location model, the propagation rules, and the step
vocabulary are our authored design; operating over the pure decoded model keeps the
service unit-testable with no IDA present. :class:`DataFlowService` also exposes a
lower-level forward primitive the taint tracer composes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Set, Tuple

from idamesh.domain.entities.data_flow import DataFlowStep
from idamesh.domain.entities.decoded_instruction import (
    DecodedInstruction,
    Operand,
    OPERAND_KIND_MEM,
    OPERAND_KIND_PHRASE,
    OPERAND_KIND_REG,
    canonical_reg,
)

#: Trace directions (authored vocabulary).
DIRECTION_FORWARD = "forward"
DIRECTION_BACKWARD = "backward"

#: Default / maximum hops a single trace will emit before reporting truncation.
DEFAULT_MAX_STEPS: int = 256
MAX_MAX_STEPS: int = 4096

#: Step-note vocabulary (authored).
NOTE_USE = "use"
NOTE_PROPAGATE = "propagate"
NOTE_TRANSFORM = "transform"
NOTE_REDEFINED = "redefined"
NOTE_DEF = "def"
NOTE_SOURCE = "source"

#: Mnemonics that are a pure copy (``dst := src``) rather than a transform.
_MOVE_MNEMONICS: frozenset = frozenset(
    {"mov", "movzx", "movsx", "movsxd", "lea", "movq", "movd"}
)


@dataclass(frozen=True)
class Location:
    """A tracked value location: a register family or a stack slot.

    ``kind`` is ``"reg"`` (``key`` is the canonical register family) or ``"stack"``
    (``key`` is the slot displacement as a string). Equality/hash on the pair make
    it usable as a set element and a taint seed.
    """

    kind: str
    key: str

    @classmethod
    def of(cls, operand: Operand) -> Optional["Location"]:
        """Derive the location an operand names, or ``None`` if it names no scalar.

        A register operand becomes a ``reg`` family location; a stack-slot phrase
        becomes a ``stack`` location; a global ``mem`` operand becomes a ``mem``
        location keyed by absolute address. Immediates name no location.
        """
        if operand.kind == OPERAND_KIND_REG and operand.reg:
            fam = canonical_reg(operand.reg)
            return cls("reg", fam) if fam else None
        slot = operand.stack_slot()
        if slot is not None:
            return cls("stack", str(slot))
        if operand.kind == OPERAND_KIND_MEM and operand.value is not None:
            return cls("mem", hex(operand.value))
        return None

    def render(self) -> str:
        """A short human label for the location (``reg:rax`` / ``stack:-8``)."""
        return f"{self.kind}:{self.key}"


class DataFlowService:
    """Bounded, heuristic intra-procedural def-use tracing over decoded code."""

    def trace(
        self,
        instructions: Sequence[DecodedInstruction],
        *,
        start: int,
        operand: int = 0,
        direction: str = DIRECTION_FORWARD,
        max_steps: int = DEFAULT_MAX_STEPS,
    ) -> Tuple[List[DataFlowStep], bool]:
        """Trace the value at ``(start, operand)`` and return ``(steps, truncated)``.

        ``start`` is an instruction *address value* (the ``ea.value`` of the anchor
        instruction). The operand at ``operand`` on that instruction fixes the
        initial location; ``direction`` selects a forward or backward walk bounded
        to ``max_steps`` hops. ``truncated`` is set when the hop budget was reached
        with instructions still unexamined. An operand that names no scalar
        location (an immediate), or a ``start`` matching no instruction, yields an
        empty trace — a valid result, not an error.
        """
        cap = self._clamp_steps(max_steps)
        anchor_index = self._index_of(instructions, start)
        if anchor_index is None:
            return [], False
        seed = self._seed_location(instructions[anchor_index], operand)
        if seed is None:
            return [], False
        if direction == DIRECTION_BACKWARD:
            return self._backward(instructions, anchor_index, seed, cap)
        return self._forward(instructions, anchor_index, {seed}, cap)

    def forward_reach(
        self,
        instructions: Sequence[DecodedInstruction],
        *,
        start_index: int,
        seeds: Iterable[Location],
        max_steps: int = DEFAULT_MAX_STEPS,
    ) -> List[Tuple[int, DecodedInstruction, "frozenset[Location]"]]:
        """Forward primitive for the taint tracer.

        Propagates ``seeds`` forward from ``start_index + 1`` and yields, for each
        instruction examined, ``(index, instruction, tainted_before)`` where
        ``tainted_before`` is the set of tainted locations *live as the instruction
        executes* (before this instruction's own writes are applied). Bounded to
        ``max_steps`` instructions. The taint tracer inspects each instruction's
        read operands against ``tainted_before`` to decide whether a sink argument
        is tainted, then lets the propagation continue.
        """
        cap = self._clamp_steps(max_steps)
        tainted: Set[Location] = set(seeds)
        out: List[Tuple[int, DecodedInstruction, "frozenset[Location]"]] = []
        examined = 0
        for index in range(start_index + 1, len(instructions)):
            if examined >= cap or not tainted:
                break
            insn = instructions[index]
            out.append((index, insn, frozenset(tainted)))
            self._apply_propagation(insn, tainted)
            examined += 1
        return out

    # -- forward / backward walks ------------------------------------------

    def _forward(
        self,
        instructions: Sequence[DecodedInstruction],
        anchor_index: int,
        seeds: Set[Location],
        cap: int,
    ) -> Tuple[List[DataFlowStep], bool]:
        """Walk forward from the anchor, emitting a step per relevant instruction."""
        tracked: Set[Location] = set(seeds)
        steps: List[DataFlowStep] = []
        truncated = False
        for index in range(anchor_index + 1, len(instructions)):
            if len(steps) >= cap:
                truncated = self._has_more(instructions, index, tracked)
                break
            if not tracked:
                break
            insn = instructions[index]
            reads = self._locations(insn, want_read=True)
            writes = self._locations(insn, want_write=True)
            touched = tracked & reads
            if touched:
                dest = self._move_destination(insn)
                if dest is not None and dest not in tracked:
                    tracked.add(dest)
                    steps.append(
                        DataFlowStep(
                            address=insn.ea,
                            insn=insn.text,
                            note=NOTE_PROPAGATE,
                            target=dest.render(),
                        )
                    )
                elif (tracked & writes):
                    steps.append(
                        DataFlowStep(
                            address=insn.ea,
                            insn=insn.text,
                            note=NOTE_TRANSFORM,
                            target=None,
                        )
                    )
                else:
                    steps.append(
                        DataFlowStep(
                            address=insn.ea,
                            insn=insn.text,
                            note=NOTE_USE,
                            target=None,
                        )
                    )
                continue
            # Not read here: a write that is not also a read kills the location.
            killed = tracked & writes
            if killed:
                for loc in killed:
                    tracked.discard(loc)
                steps.append(
                    DataFlowStep(
                        address=insn.ea,
                        insn=insn.text,
                        note=NOTE_REDEFINED,
                        target=", ".join(sorted(loc.render() for loc in killed)),
                    )
                )
        return steps, truncated

    def _backward(
        self,
        instructions: Sequence[DecodedInstruction],
        anchor_index: int,
        seed: Location,
        cap: int,
    ) -> Tuple[List[DataFlowStep], bool]:
        """Walk backward from the anchor, following the defining writes."""
        tracked: Set[Location] = {seed}
        steps: List[DataFlowStep] = []
        truncated = False
        for index in range(anchor_index - 1, -1, -1):
            if len(steps) >= cap:
                truncated = True
                break
            if not tracked:
                break
            insn = instructions[index]
            writes = self._locations(insn, want_write=True)
            defined = tracked & writes
            if not defined:
                continue
            source = self._move_source(insn)
            if source is not None:
                # A copy: the definition hops to its source location.
                for loc in defined:
                    tracked.discard(loc)
                tracked.add(source)
                steps.append(
                    DataFlowStep(
                        address=insn.ea,
                        insn=insn.text,
                        note=NOTE_DEF,
                        target=source.render(),
                    )
                )
            else:
                # A definition we cannot follow further (call result, immediate,
                # computed): record it and stop tracking the defined location.
                for loc in defined:
                    tracked.discard(loc)
                steps.append(
                    DataFlowStep(
                        address=insn.ea,
                        insn=insn.text,
                        note=NOTE_DEF,
                        target=None,
                    )
                )
        return steps, truncated

    # -- shared helpers ----------------------------------------------------

    def _apply_propagation(
        self, insn: DecodedInstruction, tainted: Set[Location]
    ) -> None:
        """Update ``tainted`` in place with one instruction's copy/kill effect."""
        reads = self._locations(insn, want_read=True)
        writes = self._locations(insn, want_write=True)
        if tainted & reads:
            dest = self._move_destination(insn)
            if dest is not None:
                tainted.add(dest)
            return
        # A write that does not read a tainted source clears the destination.
        for loc in list(tainted & writes):
            tainted.discard(loc)

    @staticmethod
    def _clamp_steps(max_steps: int) -> int:
        """Clamp a requested hop budget into ``[0, MAX_MAX_STEPS]``."""
        if max_steps <= 0:
            return 0
        return min(max_steps, MAX_MAX_STEPS)

    @staticmethod
    def _index_of(
        instructions: Sequence[DecodedInstruction], start: int
    ) -> Optional[int]:
        """Find the index of the instruction whose address equals ``start``."""
        for index, insn in enumerate(instructions):
            if insn.ea.value == start:
                return index
        return None

    @staticmethod
    def _seed_location(
        insn: DecodedInstruction, operand: int
    ) -> Optional[Location]:
        """Location named by the anchor instruction's ``operand``-th operand."""
        op = insn.operand(operand)
        if op is None:
            return None
        return Location.of(op)

    @staticmethod
    def _locations(
        insn: DecodedInstruction, *, want_read: bool = False, want_write: bool = False
    ) -> Set[Location]:
        """Collect the read (or written) scalar locations of an instruction.

        A phrase/mem operand also *reads* its base and index registers (address
        computation), so those register families are added to the read set — a
        write through ``[rax+8]`` still reads ``rax``.
        """
        found: Set[Location] = set()
        for op in insn.operands:
            loc = Location.of(op)
            if loc is not None:
                if want_read and op.is_read:
                    found.add(loc)
                if want_write and op.is_write:
                    found.add(loc)
            if want_read and op.kind in (OPERAND_KIND_PHRASE,):
                for reg in (op.base_reg, op.index_reg):
                    fam = canonical_reg(reg)
                    if fam:
                        found.add(Location("reg", fam))
        return found

    @staticmethod
    def _move_destination(insn: DecodedInstruction) -> Optional[Location]:
        """Destination location of a pure copy instruction, else ``None``."""
        if insn.mnemonic.strip().lower() not in _MOVE_MNEMONICS:
            return None
        dest = insn.operand(0)
        if dest is None or not dest.is_write:
            return None
        return Location.of(dest)

    @staticmethod
    def _move_source(insn: DecodedInstruction) -> Optional[Location]:
        """Source location of a pure copy instruction, else ``None``."""
        if insn.mnemonic.strip().lower() not in _MOVE_MNEMONICS:
            return None
        src = insn.operand(1)
        if src is None or not src.is_read:
            return None
        return Location.of(src)

    def _has_more(
        self,
        instructions: Sequence[DecodedInstruction],
        index: int,
        tracked: Set[Location],
    ) -> bool:
        """Would the forward walk still emit steps past ``index``? (truncation flag)."""
        if not tracked:
            return False
        for probe in range(index, len(instructions)):
            insn = instructions[probe]
            if tracked & (
                self._locations(insn, want_read=True)
                | self._locations(insn, want_write=True)
            ):
                return True
        return False
