"""The ``imports_query`` use-case — a filtered query over the import repository.

Walks the :class:`~idamesh.domain.ports.imports.ImportRepository` under a hard scan
bound, projects each :class:`~idamesh.domain.entities.imports.Import` into a feature
mapping, and keeps those passing the shared pure
:class:`~idamesh.domain.query.predicate.Query` assembled from the command's symbol
and module name-substring filters. The reply is capped at a clamped ``limit``.
"""

from __future__ import annotations

from typing import Iterator, List, Optional

from idamesh.application.dto.imports_query import (
    MAX_IMPORTS_QUERY_LIMIT,
    MAX_IMPORTS_QUERY_SCAN,
    ImportsQueryCommand,
    ImportsQueryResult,
)
from idamesh.domain.entities.imports import Import
from idamesh.domain.ports.imports import ImportRepository
from idamesh.domain.query.predicate import FieldOp, FieldPredicate, Query
from idamesh.domain.values.pagination import MAX_COUNT, PageRequest


def _clamp_limit(limit: int, maximum: int) -> int:
    """Bound a requested ``limit`` to ``[0, maximum]``."""
    if limit < 0:
        return 0
    return maximum if limit > maximum else limit


def _substring_predicate(field: str, value: str) -> Optional[FieldPredicate]:
    """A case-insensitive substring predicate, or ``None`` when unfiltered."""
    if not value.strip():
        return None
    return FieldPredicate(field, FieldOp.CONTAINS, value)


def _features(item: Import) -> dict:
    """Project an import into the feature mapping the query evaluates over."""
    return {"name": item.name, "module": item.module}


class ImportsQueryUseCase:
    """Filter the imported-symbol table by symbol name and originating module."""

    def __init__(self, imports_repo: ImportRepository) -> None:
        self._imports = imports_repo

    def execute(self, command: ImportsQueryCommand) -> ImportsQueryResult:
        """Walk the imports and keep those matching the assembled query."""
        limit = _clamp_limit(command.limit, MAX_IMPORTS_QUERY_LIMIT)
        query = Query.of(
            _substring_predicate("name", command.name),
            _substring_predicate("module", command.module),
        )

        matches: List[Import] = []
        truncated = False
        for item in self._walk(query):
            if len(matches) >= limit:
                truncated = True
                break
            matches.append(item)

        return ImportsQueryResult(matches=tuple(matches), truncated=truncated)

    # -- internals ---------------------------------------------------------

    def _walk(self, query: Query) -> Iterator[Import]:
        """Yield imports passing ``query``, bounded by a hard scan ceiling."""
        scanned = 0
        offset = 0
        while scanned < MAX_IMPORTS_QUERY_SCAN:
            page = self._imports.list(PageRequest(offset=offset, count=MAX_COUNT))
            items = list(page.items)
            if not items:
                return
            for item in items:
                scanned += 1
                if query.matches(_features(item)):
                    yield item
                if scanned >= MAX_IMPORTS_QUERY_SCAN:
                    return
            if not page.truncated and len(items) < MAX_COUNT:
                return
            offset += len(items)
