"""The ``entity_query`` use-case — a unified, filtered query over named entities.

Draws from the function, named-global, and import repositories (selected by the
``kind`` filter), projects each item into the shared
:class:`~idamesh.domain.entities.named_entity.NamedEntity` shape, and keeps those
whose name passes the shared pure :class:`~idamesh.domain.query.predicate.Query`.
The scan is bounded per repository and the reply is capped at a clamped ``limit``.
"""

from __future__ import annotations

import itertools
from typing import Callable, Iterator, List, Optional, Tuple

from idamesh.application.dto.entity_query import (
    ENTITY_KINDS,
    MAX_ENTITY_QUERY_LIMIT,
    MAX_ENTITY_QUERY_SCAN,
    EntityQueryCommand,
    EntityQueryResult,
)
from idamesh.domain.entities.data import Global
from idamesh.domain.entities.function import Function
from idamesh.domain.entities.imports import Import
from idamesh.domain.entities.named_entity import (
    KIND_FUNCTION,
    KIND_GLOBAL,
    KIND_IMPORT,
    NamedEntity,
)
from idamesh.domain.ports.functions import FunctionRepository
from idamesh.domain.ports.globals import GlobalRepository
from idamesh.domain.ports.imports import ImportRepository
from idamesh.domain.query.predicate import FieldOp, FieldPredicate, Query
from idamesh.domain.values.pagination import MAX_COUNT, PageRequest

#: Any object exposing ``list(PageRequest) -> Page`` — the shared repo shape.
_Source = object


def _clamp_limit(limit: int, maximum: int) -> int:
    """Bound a requested ``limit`` to ``[0, maximum]``."""
    if limit < 0:
        return 0
    return maximum if limit > maximum else limit


def _name_predicate(substring: str) -> Optional[FieldPredicate]:
    """A case-insensitive name-substring predicate, or ``None`` when unfiltered."""
    if not substring.strip():
        return None
    return FieldPredicate("name", FieldOp.CONTAINS, substring)


def _function_entity(func: Function) -> NamedEntity:
    """Project a :class:`Function` into the unified entity shape."""
    return NamedEntity(name=func.name, ea=func.ea, kind=KIND_FUNCTION, size=func.size)


def _global_entity(item: Global) -> NamedEntity:
    """Project a :class:`Global` into the unified entity shape."""
    return NamedEntity(name=item.name, ea=item.ea, kind=KIND_GLOBAL, size=item.size)


def _import_entity(item: Import) -> NamedEntity:
    """Project an :class:`Import` into the unified entity shape."""
    return NamedEntity(
        name=item.name,
        ea=item.ea,
        kind=KIND_IMPORT,
        module=item.module,
        ordinal=item.ordinal,
    )


class EntityQueryUseCase:
    """Filter functions, globals, and imports by kind and name into one stream."""

    def __init__(
        self,
        functions: FunctionRepository,
        globals_repo: GlobalRepository,
        imports_repo: ImportRepository,
    ) -> None:
        self._functions = functions
        self._globals = globals_repo
        self._imports = imports_repo

    def execute(self, command: EntityQueryCommand) -> EntityQueryResult:
        """Draw from the selected repositories and filter by the name predicate."""
        kind = (command.kind or "any").strip().lower() or "any"
        if kind not in ENTITY_KINDS:
            raise ValueError(
                f"unknown entity kind {command.kind!r}; expected one of {ENTITY_KINDS}"
            )
        limit = _clamp_limit(command.limit, MAX_ENTITY_QUERY_LIMIT)
        query = Query.of(_name_predicate(command.query))

        matches: List[NamedEntity] = []
        truncated = False
        stream = itertools.chain.from_iterable(
            self._walk(source, project, query)
            for source, project in self._sources(kind)
        )
        for entity in stream:
            if len(matches) >= limit:
                truncated = True
                break
            matches.append(entity)

        return EntityQueryResult(
            query=command.query,
            kind=kind,
            matches=tuple(matches),
            truncated=truncated,
        )

    # -- internals ---------------------------------------------------------

    def _sources(
        self, kind: str
    ) -> Tuple[Tuple[_Source, Callable[..., NamedEntity]], ...]:
        """The ``(repository, projector)`` pairs the ``kind`` filter selects."""
        table = {
            KIND_FUNCTION: (self._functions, _function_entity),
            KIND_GLOBAL: (self._globals, _global_entity),
            KIND_IMPORT: (self._imports, _import_entity),
        }
        if kind == "any":
            return (
                table[KIND_FUNCTION],
                table[KIND_GLOBAL],
                table[KIND_IMPORT],
            )
        return (table[kind],)

    @staticmethod
    def _walk(
        source: _Source,
        project: Callable[..., NamedEntity],
        query: Query,
    ) -> Iterator[NamedEntity]:
        """Yield projected entities from one repository that pass ``query``.

        Walks the repository page by page under a hard scan bound, so a huge
        symbol set can never trigger an unbounded enumeration.
        """
        scanned = 0
        offset = 0
        while scanned < MAX_ENTITY_QUERY_SCAN:
            page = source.list(PageRequest(offset=offset, count=MAX_COUNT))
            items = list(page.items)
            if not items:
                return
            for item in items:
                scanned += 1
                entity = project(item)
                if query.matches({"name": entity.name}):
                    yield entity
                if scanned >= MAX_ENTITY_QUERY_SCAN:
                    return
            if not page.truncated and len(items) < MAX_COUNT:
                return
            offset += len(items)
