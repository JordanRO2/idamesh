"""Catalog registration and wire-shape projection for ``analyze_function``.

The nested ``*View`` ``TypedDict``s give the schema compiler an object-rooted
``outputSchema``; :func:`analyze_function_view` renders the composite
:class:`~idamesh.domain.entities.analyze_function.FunctionAnalysis` into that flat
shape. The compact metric block reuses
:class:`~idamesh.interface.catalog.func_profile.FuncProfileView` and the edge
projection reuses :func:`~idamesh.interface.catalog.xrefs.xref_view`. The field
names and the bundle shape are ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.analyze_function import AnalyzeFunctionUseCase
from idamesh.application.dto.analyze_function import (
    AnalyzeFunctionCommand,
    AnalyzeFunctionResult,
)
from idamesh.domain.entities.func_profile import FuncProfile
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.catalog.func_profile import FuncProfileView
from idamesh.interface.catalog.xrefs import XrefView, xref_view
from idamesh.interface.mcp.registry import Registry


class AnalyzeFunctionView(TypedDict):
    """The composite single-function report."""

    address: str
    name: Optional[str]
    profile: FuncProfileView
    pseudocode: str
    lines: List[str]
    callers: List[XrefView]
    callees: List[XrefView]
    import_references: List[str]
    string_literals: List[str]


def _profile_view(profile: FuncProfile) -> FuncProfileView:
    return FuncProfileView(
        address=profile.address.hex(),
        name=profile.name,
        size=profile.size,
        block_count=profile.block_count,
        edge_count=profile.edge_count,
        caller_count=profile.caller_count,
        callee_count=profile.callee_count,
    )


def analyze_function_view(result: AnalyzeFunctionResult) -> AnalyzeFunctionView:
    """Project an ``analyze_function`` result into its wire shape."""
    analysis = result.analysis
    return AnalyzeFunctionView(
        address=analysis.profile.address.hex(),
        name=analysis.profile.name,
        profile=_profile_view(analysis.profile),
        pseudocode=analysis.pseudocode.text,
        lines=list(analysis.pseudocode.lines),
        callers=[xref_view(edge) for edge in analysis.callers],
        callees=[xref_view(edge) for edge in analysis.callees],
        import_references=list(analysis.import_references),
        string_literals=list(analysis.string_literals),
    )


def register_analyze_function(
    registry: Registry,
    *,
    analyze_function_use_case: AnalyzeFunctionUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``analyze_function`` against the composite-report use-case."""

    @registry.tool(name="analyze_function")
    def analyze_function(address: str) -> AnalyzeFunctionView:
        """Return a composite report for the function at or containing
        ``address``, assembled in one call from what an analyst would otherwise
        fetch tool-by-tool. The ``address`` may be a hexadecimal literal
        (``0x…``), a decimal literal, or a symbol name; it is resolved and mapped
        to its owning function first. The report bundles the function's
        ``name`` and compact ``profile`` (byte ``size``, control-flow block and
        edge counts, caller and callee degree), its decompiled ``pseudocode``
        (also split into ``lines``), the inbound ``callers`` and outbound
        ``callees`` cross-reference edges, the ``import_references`` (callee names
        that are imported symbols), and the ``string_literals`` surfaced in the
        pseudocode. An unresolvable address, an address in no function, or an
        unavailable decompiler yields an error result rather than failing the
        protocol request. Read-only."""
        command = AnalyzeFunctionCommand(address=address)
        result = run_use_case(
            executor, lambda: analyze_function_use_case.execute(command)
        )
        return analyze_function_view(result)
