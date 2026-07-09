"""Catalog registration and wire-shape projection for ``trace_source_to_sink``.

The ``DataFlowStepView`` (reused shape) / ``TaintPathView`` /
``TraceSourceToSinkView`` ``TypedDict``s give the schema compiler an object-rooted
``outputSchema``; :func:`trace_source_to_sink_view` renders each source→sink taint
path into that nested shape (addresses as ``0x`` hex). The field names mirror the
interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.trace_source_to_sink import (
    TraceSourceToSinkUseCase,
)
from idamesh.application.dto.trace_source_to_sink import (
    DEFAULT_MAX_PATHS,
    TraceSourceToSinkCommand,
    TraceSourceToSinkResult,
)
from idamesh.domain.entities.data_flow import DataFlowStep
from idamesh.domain.entities.taint import TaintPath
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class TaintStepView(TypedDict):
    """One hop of a source→sink taint path."""

    address: str
    insn: str
    note: str
    target: Optional[str]


class TaintPathView(TypedDict):
    """One source→sink taint path in a ``trace_source_to_sink`` result."""

    source: str
    sink: str
    api: str
    steps: List[TaintStepView]


class TraceSourceToSinkView(TypedDict):
    """The source→sink taint paths found over the scanned scope."""

    paths: List[TaintPathView]
    truncated: bool


def taint_step_view(step: DataFlowStep) -> TaintStepView:
    """Project one taint-path step into its wire shape (address as ``0x`` hex)."""
    return TaintStepView(
        address=step.address.hex(),
        insn=step.insn,
        note=step.note,
        target=step.target,
    )


def taint_path_view(path: TaintPath) -> TaintPathView:
    """Project one :class:`TaintPath` into its wire shape (addresses as ``0x`` hex)."""
    return TaintPathView(
        source=path.source.hex(),
        sink=path.sink.hex(),
        api=path.api,
        steps=[taint_step_view(step) for step in path.steps],
    )


def trace_source_to_sink_view(
    result: TraceSourceToSinkResult,
) -> TraceSourceToSinkView:
    """Project a ``trace_source_to_sink`` result into its wire shape."""
    return TraceSourceToSinkView(
        paths=[taint_path_view(path) for path in result.paths],
        truncated=result.truncated,
    )


def register_trace_source_to_sink(
    registry: Registry,
    *,
    trace_source_to_sink_use_case: TraceSourceToSinkUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``trace_source_to_sink`` against the taint use-case."""

    @registry.tool(name="trace_source_to_sink")
    def trace_source_to_sink(
        address: str = "",
        max_paths: int = DEFAULT_MAX_PATHS,
    ) -> TraceSourceToSinkView:
        """Find intra-procedural taint paths from input sources to dangerous sinks.

        Marks the return value of each input-producing call (``recv`` / ``read`` /
        ``fgets`` / ``ReadFile`` …) as tainted, propagates it forward through the
        function's decoded instructions, and reports each later dangerous-API call
        (``strcpy`` / ``system`` / ``memcpy`` …) whose tainted data reaches an
        argument. Each path carries the ``source`` and ``sink`` addresses (``0x``
        hex), the sink ``api`` name, and the connecting ``steps``. Pass an
        ``address`` (hex/decimal/symbol) to scope the scan to the one function
        containing it; omit it for a bounded whole-database scan. The analysis is
        intra-procedural, heuristic, and bounded to ``max_paths`` (clamped to a
        server maximum); ``truncated`` is set when a bound elided further paths. An
        empty result is valid, not an error. Read-only."""
        command = TraceSourceToSinkCommand(address=address, max_paths=max_paths)
        result = run_use_case(
            executor, lambda: trace_source_to_sink_use_case.execute(command)
        )
        return trace_source_to_sink_view(result)
