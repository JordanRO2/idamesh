"""Catalog registration and wire-shape projection for ``callees``.

The ``CalleeView`` / ``CalleesView`` ``TypedDict``s give the schema compiler an
object-rooted ``outputSchema``; :func:`callees_view` renders the resolved
function and its direct call targets into that flat shape (addresses as ``0x``
hex). The field names mirror the interoperability contract; the projection is
ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.xrefs import CalleesUseCase
from idamesh.application.dto.xrefs import CalleesCommand, CalleesResult
from idamesh.domain.entities.xref import Xref
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class CalleeView(TypedDict):
    """One directly-called function in a ``callees`` result."""

    addr: str
    name: Optional[str]


class CalleesView(TypedDict):
    """The direct callees of one resolved function ``func``."""

    func: str
    callees: List[CalleeView]
    truncated: bool


def callee_view(edge: Xref) -> CalleeView:
    """Project one call edge into its callee wire shape."""
    return CalleeView(addr=edge.target.hex(), name=edge.target_name)


def callees_view(result: CalleesResult) -> CalleesView:
    """Project a ``callees`` result into its wire shape."""
    return CalleesView(
        func=result.func.hex(),
        callees=[callee_view(edge) for edge in result.callees],
        truncated=result.truncated,
    )


def register_callees(
    registry: Registry,
    *,
    callees_use_case: CalleesUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``callees`` against the direct-callee use-case."""

    @registry.tool(name="callees")
    def callees(address: str) -> CalleesView:
        """List the functions directly called by the function at or containing
        ``address``. The ``address`` may be a hexadecimal literal (``0x…``), a
        decimal literal, or a symbol name; it is resolved and mapped to its
        owning function first. Each callee is reported once, with its entry
        ``addr`` and ``name``. An out-of-range or unresolvable address, or one
        that lies in no function, yields an error result rather than failing the
        protocol request."""
        command = CalleesCommand(address=address)
        result = run_use_case(executor, lambda: callees_use_case.execute(command))
        return callees_view(result)
