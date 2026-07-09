"""The decoded-instruction model: :class:`Operand` and :class:`DecodedInstruction`.

This is the *pure domain shape* the intra-procedural dataflow, taint, and
stack-string algorithms run over. It is deliberately a small, IDA-free abstraction
of a decoded machine instruction — just enough to reason about register / stack-slot
def-use and immediate-to-memory stores — so the algorithm services are unit-testable
on synthetic instruction sequences with no IDA present. Exactly one adapter
(:mod:`idamesh.infrastructure.ida.instruction_decode_adapter`) knows how to fill this
model from a real disassembler; everything downstream is pure.

The model, its operand-kind vocabulary, the register-family canonicalization table,
and the stack-slot predicate are all our authored design. The set of x86-64 register
aliases (``al``/``ax``/``eax``/``rax`` all name one physical register) is a published
hardware fact; the grouping into families here is ours.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from idamesh.domain.values.address import Address

# -- Operand-kind vocabulary (authored) ----------------------------------------

#: A register operand (``rax``, ``ecx`` …). ``reg`` names the register.
OPERAND_KIND_REG = "reg"
#: An immediate/constant operand. ``value`` holds the integer.
OPERAND_KIND_IMM = "imm"
#: A direct memory operand at an absolute address (a global). ``value`` holds it.
OPERAND_KIND_MEM = "mem"
#: A base(+index)+displacement memory operand — the form a stack slot takes
#: (``[rsp+0x20]`` / ``[rbp-0x8]``). ``base_reg`` / ``index_reg`` / ``disp`` describe it.
OPERAND_KIND_PHRASE = "phrase"

#: The stack/frame-pointer registers whose ``[reg+disp]`` phrases name a stack slot.
STACK_REGS: frozenset = frozenset(
    {"rsp", "esp", "sp", "rbp", "ebp", "bp"}
)


def _family_table() -> Dict[str, str]:
    """Build the register-alias → canonical-family map (authored grouping)."""
    families: Dict[str, Tuple[str, ...]] = {
        "rax": ("rax", "eax", "ax", "al", "ah"),
        "rbx": ("rbx", "ebx", "bx", "bl", "bh"),
        "rcx": ("rcx", "ecx", "cx", "cl", "ch"),
        "rdx": ("rdx", "edx", "dx", "dl", "dh"),
        "rsi": ("rsi", "esi", "si", "sil"),
        "rdi": ("rdi", "edi", "di", "dil"),
        "rbp": ("rbp", "ebp", "bp", "bpl"),
        "rsp": ("rsp", "esp", "sp", "spl"),
    }
    for n in range(8, 16):
        families[f"r{n}"] = (
            f"r{n}",
            f"r{n}d",
            f"r{n}w",
            f"r{n}b",
        )
    table: Dict[str, str] = {}
    for canonical, aliases in families.items():
        for alias in aliases:
            table[alias] = canonical
    return table


_FAMILY: Dict[str, str] = _family_table()


def canonical_reg(name: Optional[str]) -> Optional[str]:
    """Canonicalize a register name to its 64-bit family (``eax`` → ``rax``).

    Sub-register writes alias the full register for def-use purposes, so the
    trackers key on the family. An unknown register (a vector/segment/flags
    register we do not model) is returned lowercased and unchanged, which simply
    makes it its own family.
    """
    if name is None:
        return None
    key = name.strip().lower()
    return _FAMILY.get(key, key)


@dataclass(frozen=True)
class Operand:
    """One decoded operand of an instruction.

    ``kind`` selects which of the descriptive fields are meaningful:

    * ``reg`` — ``reg`` holds the register name.
    * ``imm`` — ``value`` holds the immediate integer.
    * ``mem`` — ``value`` holds the absolute address (a global).
    * ``phrase`` — ``base_reg`` (+ optional ``index_reg``) and ``disp`` describe a
      computed address; a stack slot is a ``phrase`` whose ``base_reg`` is a
      stack/frame pointer and whose ``index_reg`` is absent.

    ``size`` is the access width in bytes (used to size immediate-to-stack stores).
    ``is_read`` / ``is_write`` record how the instruction touches this operand.
    """

    index: int
    kind: str
    text: str
    reg: Optional[str] = None
    value: Optional[int] = None
    base_reg: Optional[str] = None
    index_reg: Optional[str] = None
    disp: Optional[int] = None
    size: Optional[int] = None
    is_read: bool = False
    is_write: bool = False

    def stack_slot(self) -> Optional[int]:
        """Return the stack displacement when this operand is a simple stack slot.

        A simple stack slot is a ``phrase`` based on a stack/frame-pointer register
        with no index register; its identity is the displacement (defaulting to
        ``0``). Returns ``None`` for anything else — a global, a register, an
        immediate, or an indexed access we decline to treat as a scalar slot.
        """
        if self.kind != OPERAND_KIND_PHRASE:
            return None
        if self.base_reg is None or self.base_reg.strip().lower() not in STACK_REGS:
            return None
        if self.index_reg is not None:
            return None
        return self.disp if self.disp is not None else 0


@dataclass(frozen=True)
class DecodedInstruction:
    """A decoded instruction: its address, mnemonic, and ordered operands."""

    ea: Address
    mnemonic: str
    operands: Tuple[Operand, ...] = ()

    @property
    def text(self) -> str:
        """A compact ``mnemonic op0, op1`` rendering for step annotations."""
        if not self.operands:
            return self.mnemonic
        joined = ", ".join(op.text for op in self.operands)
        return f"{self.mnemonic} {joined}"

    def operand(self, index: int) -> Optional[Operand]:
        """Return the operand at ``index`` (matching ``Operand.index``), or ``None``."""
        for op in self.operands:
            if op.index == index:
                return op
        if 0 <= index < len(self.operands):
            return self.operands[index]
        return None
