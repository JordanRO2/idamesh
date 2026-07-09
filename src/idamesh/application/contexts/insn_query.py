"""The ``insn_query`` use-case — a filtered query over a function's instructions.

Resolves the polymorphic ``address`` selector to a function, decodes it through the
single :class:`~idamesh.domain.ports.instruction_decode.InstructionDecodeGateway`
into the pure decoded model, projects each
:class:`~idamesh.domain.entities.decoded_instruction.DecodedInstruction` into a
feature mapping, and keeps those passing the shared pure
:class:`~idamesh.domain.query.predicate.Query` assembled from the mnemonic and
operand filters. The reply is capped at a clamped ``limit``.
"""

from __future__ import annotations

from typing import List, Optional, Set

from idamesh.application.dto.insn_query import (
    INSN_OPERAND_KINDS,
    MAX_INSN_QUERY_LIMIT,
    InsnQueryCommand,
    InsnQueryResult,
)
from idamesh.domain.entities.decoded_instruction import (
    DecodedInstruction,
    canonical_reg,
)
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.functions import FunctionRepository
from idamesh.domain.ports.instruction_decode import InstructionDecodeGateway
from idamesh.domain.query.predicate import FieldOp, FieldPredicate, Query
from idamesh.domain.values.address import Selector


def _clamp_limit(limit: int, maximum: int) -> int:
    """Bound a requested ``limit`` to ``[0, maximum]``."""
    if limit < 0:
        return 0
    return maximum if limit > maximum else limit


def _features(insn: DecodedInstruction) -> dict:
    """Project an instruction into the feature mapping the query evaluates over.

    ``operand_kinds`` collects the kinds of the operands present; ``regs`` collects
    every register the instruction touches, canonicalized to its 64-bit family so a
    sub-register filter (``eax``) matches a full-register use (``rax``).
    """
    kinds: Set[str] = set()
    regs: Set[str] = set()
    for op in insn.operands:
        kinds.add(op.kind)
        for raw in (op.reg, op.base_reg, op.index_reg):
            canonical = canonical_reg(raw)
            if canonical is not None:
                regs.add(canonical)
    return {"mnemonic": insn.mnemonic, "operand_kinds": kinds, "regs": regs}


class InsnQueryUseCase:
    """Filter the decoded instructions of one function by mnemonic and operands."""

    def __init__(
        self,
        decoder: InstructionDecodeGateway,
        functions: FunctionRepository,
        database: DatabaseGateway,
    ) -> None:
        self._decoder = decoder
        self._functions = functions
        self._database = database

    def execute(self, command: InsnQueryCommand) -> InsnQueryResult:
        """Resolve the function, decode it, and filter its instructions."""
        operand_kind = (command.operand_kind or "any").strip().lower() or "any"
        if operand_kind not in INSN_OPERAND_KINDS:
            raise ValueError(
                f"unknown operand kind {command.operand_kind!r}; "
                f"expected one of {INSN_OPERAND_KINDS}"
            )
        limit = _clamp_limit(command.limit, MAX_INSN_QUERY_LIMIT)

        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        instructions = self._decoder.decode_function(ea)
        containing = self._functions.get_containing(ea)
        function_name = containing.name if containing is not None else None

        query = self._build_query(command, operand_kind)

        matches: List[DecodedInstruction] = []
        truncated = False
        for insn in instructions:
            if not query.matches(_features(insn)):
                continue
            if len(matches) >= limit:
                truncated = True
                break
            matches.append(insn)

        return InsnQueryResult(
            function=function_name,
            matches=tuple(matches),
            truncated=truncated,
        )

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _build_query(command: InsnQueryCommand, operand_kind: str) -> Query:
        """Assemble the conjunction of predicates the command asks for."""
        predicates: List[Optional[FieldPredicate]] = []
        if command.mnemonic.strip():
            predicates.append(
                FieldPredicate("mnemonic", FieldOp.EQ, command.mnemonic.strip())
            )
        if operand_kind != "any":
            predicates.append(
                FieldPredicate("operand_kinds", FieldOp.HAS, operand_kind)
            )
        if command.operand_reg.strip():
            wanted = canonical_reg(command.operand_reg)
            if wanted is not None:
                predicates.append(FieldPredicate("regs", FieldOp.HAS, wanted))
        return Query.of(*predicates)
