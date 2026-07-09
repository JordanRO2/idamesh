"""Catalog registration and wire-shape projection for ``trace_data_flow``.

The ``DataFlowStepView`` / ``TraceDataFlowView`` ``TypedDict``s give the schema
compiler an object-rooted ``outputSchema``; :func:`trace_data_flow_view` renders
each def-use hop into that flat shape (address as ``0x`` hex). The field names
mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.trace_data_flow import TraceDataFlowUseCase
from idamesh.application.dto.trace_data_flow import (
    DEFAULT_MAX_STEPS,
    TraceDataFlowCommand,
    TraceDataFlowResult,
)
from idamesh.domain.entities.data_flow import DataFlowStep
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class DataFlowStepView(TypedDict):
    """One def-use hop in a ``trace_data_flow`` result."""

    address: str
    insn: str
    note: str
    target: Optional[str]


class TraceDataFlowView(TypedDict):
    """The bounded def-use trace of a value within one function."""

    start: str
    direction: str
    steps: List[DataFlowStepView]
    truncated: bool


def data_flow_step_view(step: DataFlowStep) -> DataFlowStepView:
    """Project one :class:`DataFlowStep` into its wire shape (address as ``0x`` hex)."""
    return DataFlowStepView(
        address=step.address.hex(),
        insn=step.insn,
        note=step.note,
        target=step.target,
    )


def trace_data_flow_view(result: TraceDataFlowResult) -> TraceDataFlowView:
    """Project a ``trace_data_flow`` result into its wire shape."""
    return TraceDataFlowView(
        start=result.start,
        direction=result.direction,
        steps=[data_flow_step_view(step) for step in result.steps],
        truncated=result.truncated,
    )


def register_trace_data_flow(
    registry: Registry,
    *,
    trace_data_flow_use_case: TraceDataFlowUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``trace_data_flow`` against the def-use tracer use-case."""

    @registry.tool(name="trace_data_flow")
    def trace_data_flow(
        address: str,
        operand: int = 0,
        direction: str = "forward",
        max_steps: int = DEFAULT_MAX_STEPS,
    ) -> TraceDataFlowView:
        """Trace the value at an instruction operand through one function, bounded.

        Follows the register or stack slot named by ``operand`` at ``address``
        (hex/decimal/symbol) through the containing function's decoded
        instructions: ``forward`` reports its subsequent uses, ``mov``
        propagations, in-place transforms, and the redefinition that kills it;
        ``backward`` reports the writes that defined it, hopping to a source
        location on a copy. Each step carries its ``address`` (``0x`` hex), the
        ``insn`` text, a ``note`` naming the rule (``use`` / ``propagate`` /
        ``transform`` / ``redefined`` / ``def``), and an optional ``target``
        location. The walk is intra-procedural, heuristic, and bounded to
        ``max_steps`` (clamped to a server maximum); ``truncated`` is set when the
        budget was reached with instructions still unexamined. An unresolvable
        address or one in no function yields an error result; an operand naming no
        scalar value yields an empty trace. Read-only."""
        command = TraceDataFlowCommand(
            address=address,
            operand=operand,
            direction=direction,
            max_steps=max_steps,
        )
        result = run_use_case(
            executor, lambda: trace_data_flow_use_case.execute(command)
        )
        return trace_data_flow_view(result)
