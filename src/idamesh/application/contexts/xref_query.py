"""The ``xref_query`` use-case — a filtered query over the cross-reference graph.

Resolves the polymorphic ``address`` selector against the database gateway (as the
read tools do), pulls the inbound edges (``direction="to"``) or the owning
function's outbound call edges (``direction="from"``) from the shared
:class:`~idamesh.domain.ports.xrefs.XrefRepository`, and keeps those passing the
shared pure :class:`~idamesh.domain.query.predicate.Query` assembled from the kind
and type filters. The reply is capped at a clamped ``limit``.
"""

from __future__ import annotations

from typing import List, Optional

from idamesh.application.dto.xref_query import (
    MAX_XREF_QUERY_LIMIT,
    XREF_DIRECTIONS,
    XREF_KINDS,
    XREF_TYPES,
    XrefQueryCommand,
    XrefQueryResult,
)
from idamesh.domain.entities.xref import Xref
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.xrefs import XrefRepository
from idamesh.domain.query.predicate import FieldOp, FieldPredicate, Query
from idamesh.domain.values.address import Selector


def _clamp_limit(limit: int, maximum: int) -> int:
    """Bound a requested ``limit`` to ``[0, maximum]``."""
    if limit < 0:
        return 0
    return maximum if limit > maximum else limit


def _equality_predicate(field: str, value: str) -> Optional[FieldPredicate]:
    """An equality predicate for a non-``"any"`` filter value, else ``None``."""
    normalized = (value or "any").strip().lower()
    if normalized == "any":
        return None
    return FieldPredicate(field, FieldOp.EQ, normalized)


def _features(edge: Xref) -> dict:
    """Project an edge into the feature mapping the query evaluates over."""
    return {"kind": edge.kind.value, "type": edge.ref_type.value}


class XrefQueryUseCase:
    """Filter the cross-references around one anchor by direction, kind, and type."""

    def __init__(self, xrefs: XrefRepository, database: DatabaseGateway) -> None:
        self._xrefs = xrefs
        self._database = database

    def execute(self, command: XrefQueryCommand) -> XrefQueryResult:
        """Resolve the anchor, pull the directed edges, and filter them."""
        direction = (command.direction or "to").strip().lower() or "to"
        if direction not in XREF_DIRECTIONS:
            raise ValueError(
                f"unknown direction {command.direction!r}; expected one of {XREF_DIRECTIONS}"
            )
        if (command.kind or "any").strip().lower() not in XREF_KINDS:
            raise ValueError(
                f"unknown xref kind {command.kind!r}; expected one of {XREF_KINDS}"
            )
        if (command.type or "any").strip().lower() not in XREF_TYPES:
            raise ValueError(
                f"unknown xref type {command.type!r}; expected one of {XREF_TYPES}"
            )
        limit = _clamp_limit(command.limit, MAX_XREF_QUERY_LIMIT)

        selector = Selector.parse(command.address)
        anchor = self._database.resolve(selector)
        edges = (
            self._xrefs.refs_to(anchor)
            if direction == "to"
            else self._xrefs.callees(anchor)
        )

        query = Query.of(
            _equality_predicate("kind", command.kind),
            _equality_predicate("type", command.type),
        )

        matches: List[Xref] = []
        truncated = False
        for edge in edges:
            if not query.matches(_features(edge)):
                continue
            if len(matches) >= limit:
                truncated = True
                break
            matches.append(edge)

        return XrefQueryResult(
            anchor=anchor,
            direction=direction,
            xrefs=tuple(matches),
            truncated=truncated,
        )
