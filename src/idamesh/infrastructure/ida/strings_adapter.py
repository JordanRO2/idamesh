"""IDA adapter implementing :class:`StringsRepository`.

Serves paginated slices of the database's extracted-string set. Enumeration is
address-ordered and materialized once through the lazily-built
:class:`~idamesh.infrastructure.ida.cache.strings_cache.StringsCache`, so paging
across the set reuses a single pass rather than re-walking ``idautils.Strings``.
All ``ida_*`` imports are performed lazily inside the cache so this module loads
without IDA present.
"""

from __future__ import annotations

from idamesh.domain.entities.string_item import StringItem
from idamesh.domain.values.pagination import Page, PageRequest
from idamesh.infrastructure.ida.cache.strings_cache import StringsCache


class IdaStringsRepository:
    """:class:`~idamesh.domain.ports.strings.StringsRepository` over the IDA SDK."""

    def __init__(self, cache: StringsCache | None = None) -> None:
        self._cache = cache if cache is not None else StringsCache()

    def list(self, page: PageRequest) -> Page[StringItem]:
        request = page.clamp()
        rows = self._cache.rows()
        total = len(rows)
        start = request.offset
        stop = start + request.count
        items = list(rows[start:stop])
        truncated = stop < total
        return Page(
            items=items,
            offset=start,
            count=request.count,
            total=total,
            truncated=truncated,
        )

    def count(self) -> int:
        return len(self._cache.rows())
