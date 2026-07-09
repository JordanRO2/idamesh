"""Catalog registration and wire-shape projection for ``xref_query``.

The ``XrefEdgeView`` / ``XrefQueryView`` ``TypedDict``s give the schema compiler an
object-rooted ``outputSchema``; :func:`xref_query_view` renders the resolved anchor
and its filtered edges into that flat shape (addresses as ``0x`` hex, enums as
their string value). The ``from`` key requires the functional ``TypedDict``
spelling because it collides with the Python keyword. The field names mirror the
interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.xref_query import XrefQueryUseCase
from idamesh.application.dto.xref_query import (
    DEFAULT_XREF_QUERY_LIMIT,
    XrefQueryCommand,
    XrefQueryResult,
)
from idamesh.domain.entities.xref import Xref
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry

#: One filtered cross-reference edge. ``from`` collides with the Python keyword,
#: so the functional ``TypedDict`` form is required.
XrefEdgeView = TypedDict(
    "XrefEdgeView",
    {
        "from": str,
        "to": str,
        "kind": str,
        "type": str,
        "func": Optional[str],
        "name": Optional[str],
    },
)


class XrefQueryView(TypedDict):
    """The cross-references around one resolved anchor that matched the query."""

    anchor: str
    direction: str
    xrefs: List[XrefEdgeView]
    truncated: bool


def xref_edge_view(edge: Xref) -> XrefEdgeView:
    """Project one :class:`Xref` edge into its filtered wire shape."""
    return {
        "from": edge.source.hex(),
        "to": edge.target.hex(),
        "kind": edge.kind.value,
        "type": edge.ref_type.value,
        "func": edge.source_func,
        "name": edge.target_name,
    }


def xref_query_view(result: XrefQueryResult) -> XrefQueryView:
    """Project an ``xref_query`` result into its wire shape."""
    return XrefQueryView(
        anchor=result.anchor.hex(),
        direction=result.direction,
        xrefs=[xref_edge_view(edge) for edge in result.xrefs],
        truncated=result.truncated,
    )


def register_xref_query(
    registry: Registry,
    *,
    xref_query_use_case: XrefQueryUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``xref_query`` against the cross-reference-filter use-case."""

    @registry.tool(name="xref_query")
    def xref_query(
        address: str,
        direction: str = "to",
        kind: str = "any",
        type: str = "any",
        limit: int = DEFAULT_XREF_QUERY_LIMIT,
    ) -> XrefQueryView:
        """Query the cross-references around ``address`` with kind/type filters. The
        ``address`` may be a hexadecimal literal (``0x…``), a decimal literal, or a
        symbol name; it is resolved to a concrete anchor first. ``direction`` is
        ``"to"`` (edges pointing at the anchor) or ``"from"`` (the call edges
        leaving the function that owns it). ``kind`` filters on ``"code"`` /
        ``"data"`` and ``type`` on ``"call"`` / ``"jump"`` / ``"read"`` /
        ``"write"`` / ``"offset"`` / ``"ordinary"``; ``"any"`` leaves that axis
        unfiltered. ``limit`` caps how many edges are returned (clamped to a server
        maximum). Each edge carries the referring ``from`` and referred ``to``
        addresses (``0x``-hex), its ``kind`` and ``type``, the enclosing ``func`` of
        the source, and the ``name`` at the target; ``truncated`` is set when the
        cap elided edges. An out-of-range or unresolvable address yields an error
        result rather than failing the protocol request. Read-only."""
        command = XrefQueryCommand(
            address=address,
            direction=direction,
            kind=kind,
            type=type,
            limit=limit,
        )
        result = run_use_case(
            executor, lambda: xref_query_use_case.execute(command)
        )
        return xref_query_view(result)
