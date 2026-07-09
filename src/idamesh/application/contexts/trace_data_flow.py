"""The trace_data_flow use-case.

Resolves an anchor address to its containing function, decodes the function
through the single
:class:`~idamesh.domain.ports.instruction_decode.InstructionDecodeGateway` adapter,
and runs the pure
:class:`~idamesh.domain.services.data_flow.DataFlowService` def-use tracer over the
decoded instructions — bounded, intra-procedural, heuristic. No new adapter beyond
the shared decoder.
"""

from __future__ import annotations

from idamesh.application.dto.trace_data_flow import (
    MAX_MAX_STEPS,
    TraceDataFlowCommand,
    TraceDataFlowResult,
)
from idamesh.domain.entities.function import Function
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.functions import FunctionRepository
from idamesh.domain.ports.instruction_decode import InstructionDecodeGateway
from idamesh.domain.services.data_flow import DataFlowService
from idamesh.domain.values.address import Selector


class TraceDataFlowUseCase:
    """Trace the value at an ``(address, operand)`` forward or backward, bounded.

    The anchor ``address`` is resolved and its containing function decoded; the
    dataflow service follows the operand's value through the function's
    instructions in the requested direction, up to the clamped ``max_steps``. An
    unresolvable address, or an address in no function, surfaces as an error the
    interface renders as an ``isError`` result. An anchor that is not the first
    byte of a decoded instruction, or an operand that names no scalar value, yields
    an empty (valid) trace.
    """

    def __init__(
        self,
        decoder: InstructionDecodeGateway,
        data_flow: DataFlowService,
        functions: FunctionRepository,
        database: DatabaseGateway,
    ) -> None:
        self._decoder = decoder
        self._data_flow = data_flow
        self._functions = functions
        self._database = database

    def execute(self, command: TraceDataFlowCommand) -> TraceDataFlowResult:
        """Resolve the anchor, decode its function, and run the def-use trace."""
        func = self._resolve_function(command.address)
        anchor = self._database.resolve(Selector.parse(command.address))
        instructions = self._decoder.decode_function(func.ea)
        steps, truncated = self._data_flow.trace(
            instructions,
            start=anchor.value,
            operand=command.operand,
            direction=command.direction,
            max_steps=min(max(command.max_steps, 0), MAX_MAX_STEPS),
        )
        return TraceDataFlowResult(
            start=anchor.hex(),
            direction=command.direction,
            steps=tuple(steps),
            truncated=truncated,
        )

    # -- internals ---------------------------------------------------------

    def _resolve_function(self, address: str) -> Function:
        """Resolve a selector to the function that contains it."""
        selector = Selector.parse(address)
        ea = self._database.resolve(selector)
        func = self._functions.get_containing(ea)
        if func is None:
            raise ValueError(f"no function contains address {ea.hex()}")
        return func
