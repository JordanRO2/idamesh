"""Catalog registration and wire-shape projection for ``entity_query``.

The ``EntityMatchView`` / ``EntityQueryView`` ``TypedDict``s give the schema
compiler an object-rooted ``outputSchema``; :func:`entity_query_view` renders each
matched :class:`~idamesh.domain.entities.named_entity.NamedEntity` into that flat
shape (address as ``0x`` hex, kind-specific extras null where they do not apply).
The field names mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.entity_query import EntityQueryUseCase
from idamesh.application.dto.entity_query import (
    DEFAULT_ENTITY_QUERY_LIMIT,
    EntityQueryCommand,
    EntityQueryResult,
)
from idamesh.domain.entities.named_entity import NamedEntity
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class EntityMatchView(TypedDict):
    """One matched named entity in an ``entity_query`` result."""

    name: str
    address: str
    kind: str
    size: Optional[int]
    module: Optional[str]
    ordinal: Optional[int]


class EntityQueryView(TypedDict):
    """The named entities that matched the query."""

    query: str
    kind: str
    matches: List[EntityMatchView]
    truncated: bool


def entity_match_view(entity: NamedEntity) -> EntityMatchView:
    """Project one :class:`NamedEntity` into its wire shape."""
    return EntityMatchView(
        name=entity.name,
        address=entity.ea.hex(),
        kind=entity.kind,
        size=entity.size,
        module=entity.module,
        ordinal=entity.ordinal,
    )


def entity_query_view(result: EntityQueryResult) -> EntityQueryView:
    """Project an ``entity_query`` result into its wire shape."""
    return EntityQueryView(
        query=result.query,
        kind=result.kind,
        matches=[entity_match_view(entity) for entity in result.matches],
        truncated=result.truncated,
    )


def register_entity_query(
    registry: Registry,
    *,
    entity_query_use_case: EntityQueryUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``entity_query`` against the unified entity-query use-case."""

    @registry.tool(name="entity_query")
    def entity_query(
        query: str = "",
        kind: str = "any",
        limit: int = DEFAULT_ENTITY_QUERY_LIMIT,
    ) -> EntityQueryView:
        """Search the database's named entities — functions, named globals, and
        imported symbols — as one filtered stream. ``query`` matches a
        case-insensitive substring of each entity's name (empty matches all).
        ``kind`` restricts the search to one entity kind (``"function"`` /
        ``"global"`` / ``"import"``) or spans all three when ``"any"``. ``limit``
        caps how many matches are returned (clamped to a server maximum). Each
        match carries its ``name``, entry/slot ``address`` (``0x``-hex), the
        ``kind`` it came from, and the kind-specific extras — ``size`` for
        functions and globals, ``module`` and ``ordinal`` for imports — left null
        where they do not apply. ``truncated`` is set when the cap elided further
        matches. Read-only."""
        command = EntityQueryCommand(query=query, kind=kind, limit=limit)
        result = run_use_case(
            executor, lambda: entity_query_use_case.execute(command)
        )
        return entity_query_view(result)
