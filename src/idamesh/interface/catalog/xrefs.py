"""Catalog registration and wire-shape projection for ``xrefs_to``.

The ``XrefView`` / ``XrefsToView`` ``TypedDict``s give the schema compiler an
object-rooted ``outputSchema``; :func:`xrefs_to_view` renders the resolved
target and its inbound edges into that flat shape (addresses as ``0x`` hex,
enums as their string value). The ``from`` key requires the functional
``TypedDict`` spelling because it collides with the Python keyword. The field
names mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.xrefs import XrefsToUseCase
from idamesh.application.dto.xrefs import XrefsToCommand, XrefsToResult
from idamesh.domain.entities.xref import Xref
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry

#: One inbound cross-reference edge. ``from`` collides with the Python keyword,
#: so the functional ``TypedDict`` form is required.
XrefView = TypedDict(
    "XrefView",
    {
        "from": str,
        "to": str,
        "kind": str,
        "type": str,
        "func": Optional[str],
    },
)


class XrefsToView(TypedDict):
    """The cross-references pointing at one resolved ``target``."""

    target: str
    xrefs: List[XrefView]
    truncated: bool


def xref_view(edge: Xref) -> XrefView:
    """Project one :class:`Xref` edge into its inbound wire shape."""
    return {
        "from": edge.source.hex(),
        "to": edge.target.hex(),
        "kind": edge.kind.value,
        "type": edge.ref_type.value,
        "func": edge.source_func,
    }


def xrefs_to_view(result: XrefsToResult) -> XrefsToView:
    """Project an ``xrefs_to`` result into its wire shape."""
    return XrefsToView(
        target=result.target.hex(),
        xrefs=[xref_view(edge) for edge in result.xrefs],
        truncated=result.truncated,
    )


def register_xrefs_to(
    registry: Registry,
    *,
    xrefs_to_use_case: XrefsToUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``xrefs_to`` against the inbound cross-reference use-case."""

    @registry.tool(name="xrefs_to")
    def xrefs_to(address: str) -> XrefsToView:
        """List the cross-references that point at ``address``. The ``address``
        may be a hexadecimal literal (``0x…``), a decimal literal, or a symbol
        name; it is resolved to a concrete target first. Each edge carries the
        referring ``from`` address, the enclosing ``func`` name when the source
        is inside a function, the ``kind`` (``code``/``data``), and the finer
        ``type`` (``call``/``jump``/``read``/``write``/…). An out-of-range or
        unresolvable address yields an error result rather than failing the
        protocol request."""
        command = XrefsToCommand(address=address)
        result = run_use_case(executor, lambda: xrefs_to_use_case.execute(command))
        return xrefs_to_view(result)
