"""The ``lookup_funcs`` use-case.

Reuses the :class:`~idamesh.domain.ports.functions.FunctionRepository` and filters
the function set by a case-insensitive name substring in the application layer — a
*pure* filter, so no new adapter is needed. Each hit is projected to the compact
:class:`~idamesh.domain.entities.func_ref.FuncRef` (name + address); the reply is
capped at :data:`MAX_LOOKUP_LIMIT` with ``truncated`` set when the cap elided
matches.
"""

from __future__ import annotations

from typing import List

from idamesh.application.dto.lookup_funcs import (
    MAX_LOOKUP_LIMIT,
    LookupFuncsCommand,
    LookupFuncsResult,
)
from idamesh.domain.entities.func_ref import FuncRef
from idamesh.domain.ports.functions import FunctionRepository
from idamesh.domain.values.pagination import MAX_COUNT, PageRequest

#: How many functions to pull from the repository per enumeration round-trip.
#: The repository exposes only a paged ``list``; we walk it a full page at a
#: time (the largest a request clamps to) until the set is exhausted.
_SCAN_PAGE_SIZE: int = MAX_COUNT


class LookupFuncsUseCase:
    """Find functions whose name contains a query substring."""

    def __init__(self, functions: FunctionRepository) -> None:
        self._functions = functions

    def execute(self, command: LookupFuncsCommand) -> LookupFuncsResult:
        """Enumerate functions and keep those whose name contains ``command.query``.

        The comparison is case-insensitive; each surviving function is mapped to a
        :class:`~idamesh.domain.entities.func_ref.FuncRef`. Matches accumulate up
        to the ``limit`` clamped to :data:`MAX_LOOKUP_LIMIT`, and ``truncated`` is
        set when the cap stopped the scan before the function set was exhausted.
        """
        limit = _clamp_limit(command.limit)
        needle = command.query.casefold()

        matches: List[FuncRef] = []
        truncated = False
        offset = 0
        while not truncated:
            page = self._functions.list(
                PageRequest(offset=offset, count=_SCAN_PAGE_SIZE)
            )
            items = list(page.items)
            if not items:
                break
            for function in items:
                if needle not in function.name.casefold():
                    continue
                if len(matches) >= limit:
                    # A further match exists that the cap excludes.
                    truncated = True
                    break
                matches.append(FuncRef(address=function.ea, name=function.name))
            if len(items) < _SCAN_PAGE_SIZE:
                # A short page means the function set is exhausted.
                break
            offset += len(items)

        return LookupFuncsResult(
            query=command.query,
            matches=tuple(matches),
            truncated=truncated,
        )


def _clamp_limit(limit: int) -> int:
    """Bound a requested ``limit`` to ``[0, MAX_LOOKUP_LIMIT]``.

    A negative request degenerates to zero (no matches returned); an oversized
    request is capped at :data:`MAX_LOOKUP_LIMIT` so a client cannot force an
    unbounded scan payload.
    """
    if limit < 0:
        return 0
    if limit > MAX_LOOKUP_LIMIT:
        return MAX_LOOKUP_LIMIT
    return limit
