"""The ``func_query`` use-case — a filtered query over the function repository.

Walks the :class:`~idamesh.domain.ports.functions.FunctionRepository` under a hard
scan bound, projects each :class:`~idamesh.domain.entities.function.Function` into a
feature mapping, and keeps those passing the shared pure
:class:`~idamesh.domain.query.predicate.Query` assembled from the command's name /
size / library / thunk filters. The reply is capped at a clamped ``limit``.
"""

from __future__ import annotations

from typing import Iterator, List, Optional

from idamesh.application.dto.func_query import (
    MAX_FUNC_QUERY_LIMIT,
    MAX_FUNC_QUERY_SCAN,
    FuncQueryCommand,
    FuncQueryResult,
)
from idamesh.domain.entities.function import Function
from idamesh.domain.ports.functions import FunctionRepository
from idamesh.domain.query.predicate import FieldOp, FieldPredicate, Query
from idamesh.domain.values.pagination import MAX_COUNT, PageRequest


def _clamp_limit(limit: int, maximum: int) -> int:
    """Bound a requested ``limit`` to ``[0, maximum]``."""
    if limit < 0:
        return 0
    return maximum if limit > maximum else limit


def _flag_predicate(field: str, wanted: Optional[bool]) -> Optional[FieldPredicate]:
    """A boolean-flag predicate, or ``None`` when the tri-state filter is unset."""
    if wanted is None:
        return None
    return FieldPredicate(field, FieldOp.IS_TRUE if wanted else FieldOp.IS_FALSE)


def _build_query(command: FuncQueryCommand) -> Query:
    """Assemble the conjunction of predicates the command asks for."""
    predicates: List[Optional[FieldPredicate]] = []
    if command.name.strip():
        predicates.append(FieldPredicate("name", FieldOp.CONTAINS, command.name))
    if command.min_size > 0:
        predicates.append(FieldPredicate("size", FieldOp.GE, command.min_size))
    if command.max_size > 0:
        predicates.append(FieldPredicate("size", FieldOp.LE, command.max_size))
    predicates.append(_flag_predicate("is_library", command.is_library))
    predicates.append(_flag_predicate("is_thunk", command.is_thunk))
    return Query.of(*predicates)


def _features(func: Function) -> dict:
    """Project a function into the feature mapping the query evaluates over."""
    return {
        "name": func.name,
        "size": func.size,
        "is_library": func.is_library,
        "is_thunk": func.is_thunk,
    }


class FuncQueryUseCase:
    """Filter the function set by name, size band, and library/thunk flags."""

    def __init__(self, functions: FunctionRepository) -> None:
        self._functions = functions

    def execute(self, command: FuncQueryCommand) -> FuncQueryResult:
        """Walk the functions and keep those matching the assembled query."""
        limit = _clamp_limit(command.limit, MAX_FUNC_QUERY_LIMIT)
        query = _build_query(command)

        matches: List[Function] = []
        truncated = False
        for func in self._walk(query):
            if len(matches) >= limit:
                truncated = True
                break
            matches.append(func)

        return FuncQueryResult(matches=tuple(matches), truncated=truncated)

    # -- internals ---------------------------------------------------------

    def _walk(self, query: Query) -> Iterator[Function]:
        """Yield functions passing ``query``, bounded by a hard scan ceiling."""
        scanned = 0
        offset = 0
        while scanned < MAX_FUNC_QUERY_SCAN:
            page = self._functions.list(PageRequest(offset=offset, count=MAX_COUNT))
            items = list(page.items)
            if not items:
                return
            for func in items:
                scanned += 1
                if query.matches(_features(func)):
                    yield func
                if scanned >= MAX_FUNC_QUERY_SCAN:
                    return
            if not page.truncated and len(items) < MAX_COUNT:
                return
            offset += len(items)
