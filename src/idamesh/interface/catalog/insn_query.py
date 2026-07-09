"""Catalog registration and wire-shape projection for ``insn_query``.

The ``InsnMatchView`` / ``InsnQueryView`` ``TypedDict``s give the schema compiler an
object-rooted ``outputSchema``; :func:`insn_query_view` renders each matched
:class:`~idamesh.domain.entities.decoded_instruction.DecodedInstruction` into that
flat shape (address as ``0x`` hex, ``text`` its compact rendering). The field names
mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.insn_query import InsnQueryUseCase
from idamesh.application.dto.insn_query import (
    DEFAULT_INSN_QUERY_LIMIT,
    InsnQueryCommand,
    InsnQueryResult,
)
from idamesh.domain.entities.decoded_instruction import DecodedInstruction
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class InsnMatchView(TypedDict):
    """One matched instruction in an ``insn_query`` result."""

    address: str
    mnemonic: str
    text: str


class InsnQueryView(TypedDict):
    """The instructions of one function that matched the query."""

    function: Optional[str]
    matches: List[InsnMatchView]
    truncated: bool


def insn_match_view(insn: DecodedInstruction) -> InsnMatchView:
    """Project one :class:`DecodedInstruction` into its wire shape."""
    return InsnMatchView(
        address=insn.ea.hex(),
        mnemonic=insn.mnemonic,
        text=insn.text,
    )


def insn_query_view(result: InsnQueryResult) -> InsnQueryView:
    """Project an ``insn_query`` result into its wire shape."""
    return InsnQueryView(
        function=result.function,
        matches=[insn_match_view(insn) for insn in result.matches],
        truncated=result.truncated,
    )


def register_insn_query(
    registry: Registry,
    *,
    insn_query_use_case: InsnQueryUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``insn_query`` against the instruction-filter use-case."""

    @registry.tool(name="insn_query")
    def insn_query(
        address: str,
        mnemonic: str = "",
        operand_kind: str = "any",
        operand_reg: str = "",
        limit: int = DEFAULT_INSN_QUERY_LIMIT,
    ) -> InsnQueryView:
        """Filter the decoded instructions of the function at ``address``. The
        ``address`` may be a hexadecimal literal (``0x…``), a decimal literal, or a
        symbol name; it is resolved to the containing function, which is decoded and
        scanned. ``mnemonic`` requires an exact (case-insensitive) mnemonic when
        non-empty. ``operand_kind`` requires the instruction to carry at least one
        operand of that kind (``"reg"`` / ``"imm"`` / ``"mem"`` / ``"phrase"``);
        ``"any"`` does not filter. ``operand_reg`` requires the instruction to
        reference that register in some operand, matched on the canonical 64-bit
        family so ``eax`` also matches a use of ``rax``; empty does not filter.
        ``limit`` caps how many matches are returned (clamped to a server maximum).
        Each match carries its ``address`` (``0x``-hex), ``mnemonic``, and a compact
        ``text`` rendering; ``function`` names the enclosing function and
        ``truncated`` is set when the cap elided matches. An unresolvable or
        out-of-function address yields an error result. Read-only."""
        command = InsnQueryCommand(
            address=address,
            mnemonic=mnemonic,
            operand_kind=operand_kind,
            operand_reg=operand_reg,
            limit=limit,
        )
        result = run_use_case(
            executor, lambda: insn_query_use_case.execute(command)
        )
        return insn_query_view(result)
