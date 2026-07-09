"""The stack-string service — pure, IDA-free, over the decoded model.

:class:`StackStringService` reconstructs strings assembled on the stack by
immediate stores. It scans a function's decoded instructions for stores of an
immediate into a stack slot (``mov [rsp/rbp+disp], imm``), lays the immediate's
bytes down at the slot's displacement range, and then reads back maximal runs of
consecutive, printable bytes as candidate strings. A run must be at least
``min_length`` printable bytes to be reported; a store of a zero byte (a NUL
terminator) ends a run.

The whole heuristic — treating consecutive immediate-to-stack-slot stores as a
byte-assembled buffer, the printable-run reconstruction, and the terminator
handling — is our authored design. Operating purely over the decoded-instruction
model keeps the service fully unit-testable with no IDA present.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from idamesh.domain.entities.decoded_instruction import (
    DecodedInstruction,
    Operand,
    OPERAND_KIND_IMM,
)
from idamesh.domain.entities.stack_string import StackString
from idamesh.domain.values.address import Address

#: The minimum printable-run length reported by default (authored threshold).
DEFAULT_MIN_LENGTH: int = 4
#: Inclusive printable-byte band used to gate a run (space through tilde).
_PRINTABLE_LO: int = 0x20
_PRINTABLE_HI: int = 0x7E
#: Mnemonics whose first operand may be an immediate-to-memory store we honor.
_STORE_MNEMONICS: frozenset = frozenset({"mov", "movb", "movw", "movd", "movq"})


@dataclass(frozen=True)
class _Store:
    """One immediate-to-stack-slot store: its slot range and the bytes written."""

    disp: int
    order: int
    ea_value: int
    data: bytes


def _is_printable(byte: int) -> bool:
    """``True`` when a byte falls in the reported printable band."""
    return _PRINTABLE_LO <= byte <= _PRINTABLE_HI


def _little_endian(value: int, width: int) -> bytes:
    """Encode ``value`` as ``width`` little-endian bytes (two's-complement wrap)."""
    if width <= 0:
        width = 1
    masked = value & ((1 << (8 * width)) - 1)
    return masked.to_bytes(width, "little")


class StackStringService:
    """Reconstruct stack-assembled strings from a function's decoded instructions."""

    def detect(
        self,
        instructions: Sequence[DecodedInstruction],
        *,
        function: Optional[str] = None,
        min_length: int = DEFAULT_MIN_LENGTH,
    ) -> List[StackString]:
        """Return the stack strings assembled across ``instructions``.

        Immediate-to-stack-slot stores are collected per base register and laid
        down at their displacement ranges; maximal runs of consecutive printable
        bytes at least ``min_length`` long are read back as
        :class:`StackString` findings, each anchored at the earliest store that
        contributes a byte to the run. A zero byte terminates a run. The scan is
        linear in the instruction count; an empty result is valid (sparse), not an
        error.
        """
        threshold = min_length if min_length > 0 else DEFAULT_MIN_LENGTH
        by_base: Dict[str, List[_Store]] = {}

        for order, insn in enumerate(instructions):
            store = self._as_store(insn, order)
            if store is None:
                continue
            base_key, record = store
            by_base.setdefault(base_key, []).append(record)

        matches: List[StackString] = []
        for stores in by_base.values():
            matches.extend(self._runs(stores, function, threshold))

        # Deterministic order: by anchor address, then by value.
        matches.sort(key=lambda m: (m.address.value, m.value))
        return matches

    # -- internals ---------------------------------------------------------

    def _as_store(
        self, insn: DecodedInstruction, order: int
    ) -> Optional[Tuple[str, _Store]]:
        """Recognize ``mov [stack_slot], imm`` and return its base key + record."""
        if insn.mnemonic.strip().lower() not in _STORE_MNEMONICS:
            return None
        if len(insn.operands) < 2:
            return None
        dest = insn.operand(0)
        src = insn.operand(1)
        if dest is None or src is None:
            return None
        if src.kind != OPERAND_KIND_IMM or src.value is None:
            return None
        slot = dest.stack_slot()
        if slot is None or not dest.is_write:
            return None
        width = self._store_width(dest, src)
        data = _little_endian(int(src.value), width)
        base_key = (dest.base_reg or "").strip().lower()
        return base_key, _Store(
            disp=slot, order=order, ea_value=insn.ea.value, data=data
        )

    @staticmethod
    def _store_width(dest: Operand, src: Operand) -> int:
        """Pick the store width in bytes from the memory then immediate operand."""
        if dest.size and dest.size > 0:
            return dest.size
        if src.size and src.size > 0:
            return src.size
        return 1

    def _runs(
        self,
        stores: List[_Store],
        function: Optional[str],
        threshold: int,
    ) -> List[StackString]:
        """Lay stores into a byte map, then read back printable runs."""
        # Later stores to the same byte win; iterate in program order so a
        # rewrite of a slot supersedes the earlier value.
        byte_at: Dict[int, int] = {}
        ea_at: Dict[int, int] = {}
        for store in sorted(stores, key=lambda s: s.order):
            for offset, byte in enumerate(store.data):
                pos = store.disp + offset
                byte_at[pos] = byte
                ea_at[pos] = store.ea_value

        results: List[StackString] = []
        if not byte_at:
            return results

        positions = sorted(byte_at)
        run_chars: List[str] = []
        run_eas: List[int] = []
        prev_pos: Optional[int] = None

        def flush() -> None:
            if len(run_chars) >= threshold:
                anchor = min(run_eas)
                results.append(
                    StackString(
                        address=Address(anchor),
                        value="".join(run_chars),
                        function=function,
                    )
                )
            run_chars.clear()
            run_eas.clear()

        for pos in positions:
            byte = byte_at[pos]
            contiguous = prev_pos is not None and pos == prev_pos + 1
            if not contiguous:
                flush()
            if _is_printable(byte):
                run_chars.append(chr(byte))
                run_eas.append(ea_at[pos])
            else:
                # A non-printable byte (a NUL terminator or a gap) ends the run.
                flush()
            prev_pos = pos
        flush()
        return results
