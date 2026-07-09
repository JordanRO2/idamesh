"""The find_dangerous_callers use-case.

Matches the module's imports against the pure
:class:`~idamesh.domain.services.dangerous_apis.DangerousApiService`
classification, then collects each dangerous import's call sites through the
reused :class:`~idamesh.domain.ports.xrefs.XrefRepository` — no new adapter. The
whole import table is walked page by page through the reused
:class:`~idamesh.domain.ports.imports.ImportRepository`, and each call site is
attributed to its enclosing function (via the xref, falling back to the
:class:`~idamesh.domain.ports.functions.FunctionRepository`).
"""

from __future__ import annotations

from typing import Dict, List

from idamesh.application.dto.find_dangerous_callers import (
    MAX_CALLER_LIMIT,
    FindDangerousCallersCommand,
    FindDangerousCallersResult,
)
from idamesh.domain.entities.dangerous_caller import (
    DangerousApiMatch,
    DangerousCaller,
)
from idamesh.domain.ports.functions import FunctionRepository
from idamesh.domain.ports.imports import ImportRepository
from idamesh.domain.ports.xrefs import XrefRepository
from idamesh.domain.services.dangerous_apis import DangerousApiService
from idamesh.domain.values.pagination import MAX_COUNT, PageRequest

#: Ceiling on import pages walked, so a pathological import table cannot make the
#: scan unbounded even before the caller's match ``limit`` bites.
_MAX_PAGES: int = 1000


class FindDangerousCallersUseCase:
    """Find every call site that reaches a dangerous imported API.

    Walks the import table, classifies each import through the
    :class:`~idamesh.domain.services.dangerous_apis.DangerousApiService`, and for
    every dangerous import collects the cross-references pointing at its import
    slot as call sites — each attributed to its enclosing function. Sites are
    grouped under the import name and the aggregate is capped at the clamped
    ``limit``, with ``truncated`` set when the cap (or the page ceiling) elided
    further sites.
    """

    def __init__(
        self,
        imports: ImportRepository,
        xrefs: XrefRepository,
        functions: FunctionRepository,
        danger: DangerousApiService,
    ) -> None:
        self._imports = imports
        self._xrefs = xrefs
        self._functions = functions
        self._danger = danger

    def execute(
        self, command: FindDangerousCallersCommand
    ) -> FindDangerousCallersResult:
        """Match imports against the danger table and collect their call sites.

        The import table is paged through in address order. Each import that
        classifies as dangerous has its inbound references collected as call
        sites (``address`` plus enclosing ``function``), grouped under the import
        name in first-seen order. The total number of collected sites is bounded
        by the clamped ``limit``; ``truncated`` is set when the budget was
        reached — or the page ceiling hit — with dangerous sites still
        uncollected.
        """
        limit = min(command.limit, MAX_CALLER_LIMIT)
        if limit < 0:
            limit = 0

        grouped: Dict[str, List[DangerousCaller]] = {}
        order: List[str] = []
        collected = 0
        truncated = False

        offset = 0
        pages = 0
        while pages < _MAX_PAGES:
            page = self._imports.list(PageRequest(offset=offset, count=MAX_COUNT))
            items = list(page.items)
            if not items:
                break
            for imported in items:
                if collected >= limit:
                    truncated = True
                    break
                if not self._danger.is_dangerous(imported.name):
                    continue
                bucket = grouped.get(imported.name)
                if bucket is None:
                    bucket = []
                    grouped[imported.name] = bucket
                    order.append(imported.name)
                for ref in self._xrefs.refs_to(imported.ea):
                    if collected >= limit:
                        truncated = True
                        break
                    bucket.append(
                        DangerousCaller(
                            address=ref.source,
                            function=self._enclosing(ref),
                        )
                    )
                    collected += 1
            if truncated:
                break
            if not page.truncated and len(items) < MAX_COUNT:
                break
            offset += len(items)
            pages += 1

        matches = tuple(
            DangerousApiMatch(api=name, callers=tuple(grouped[name]))
            for name in order
            if grouped[name]
        )
        return FindDangerousCallersResult(matches=matches, truncated=truncated)

    def _enclosing(self, ref) -> str | None:  # type: ignore[no-untyped-def]
        """Name the function a call site sits in.

        Prefers the enclosing-function name the cross-reference already carries;
        falls back to a point lookup through the function repository when the
        edge did not attribute one.
        """
        if ref.source_func:
            return ref.source_func
        func = self._functions.get_containing(ref.source)
        return func.name if func is not None else None
