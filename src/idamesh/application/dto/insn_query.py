"""Command/Result DTOs for ``insn_query``.

A filtered query over the decoded instructions of one function, obtained through
the :class:`~idamesh.domain.ports.instruction_decode.InstructionDecodeGateway`.
``mnemonic`` filters by exact (case-insensitive) mnemonic; ``operand_kind`` and
``operand_reg`` filter by an operand the instruction touches. The result is a
bounded, ``truncated``-flagged list of matched
:class:`~idamesh.domain.entities.decoded_instruction.DecodedInstruction`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from idamesh.domain.entities.decoded_instruction import DecodedInstruction

#: Matches returned when an ``insn_query`` client omits ``limit``.
DEFAULT_INSN_QUERY_LIMIT: int = 200
#: Hard ceiling a requested ``insn_query`` ``limit`` is clamped to.
MAX_INSN_QUERY_LIMIT: int = 2000
#: The accepted ``operand_kind`` filter values (``"any"`` does not filter).
INSN_OPERAND_KINDS: Tuple[str, ...] = ("any", "reg", "imm", "mem", "phrase")


@dataclass(frozen=True)
class InsnQueryCommand:
    """Input for ``insn_query``.

    ``address`` is a hex/decimal/symbol selector resolved to a function, whose
    instructions are decoded and filtered. ``mnemonic`` requires an exact
    (case-insensitive) mnemonic when non-empty. ``operand_kind`` requires the
    instruction to carry at least one operand of that kind (``reg`` / ``imm`` /
    ``mem`` / ``phrase``); ``"any"`` does not filter. ``operand_reg`` requires the
    instruction to reference that register (matched on the canonical 64-bit family)
    in some operand; empty does not filter. ``limit`` bounds the matches and is
    clamped to a server maximum.
    """

    address: str
    mnemonic: str = ""
    operand_kind: str = "any"
    operand_reg: str = ""
    limit: int = DEFAULT_INSN_QUERY_LIMIT


@dataclass(frozen=True)
class InsnQueryResult:
    """Output for ``insn_query`` — the matched instructions of the function."""

    function: Optional[str]
    matches: Tuple[DecodedInstruction, ...]
    truncated: bool = False
