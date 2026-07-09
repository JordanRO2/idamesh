"""The ``search_structs`` use-case.

Programs against the :class:`~idamesh.domain.ports.structs.StructGateway`,
filtering the aggregate-type set by a case-insensitive name substring. The
requested ``limit`` is clamped to a server maximum; the gateway is asked for one
match beyond the cap so ``truncated`` can be set without a second round-trip, and
the surplus is trimmed before returning. No SDK logic lives here — the gateway
supplies the struct summaries.
"""

from __future__ import annotations

from idamesh.application.dto.search_structs import (
    MAX_SEARCH_STRUCTS_LIMIT,
    SearchStructsCommand,
    SearchStructsResult,
)
from idamesh.domain.ports.structs import StructGateway


class SearchStructsUseCase:
    """Find aggregate (struct/union) types whose name contains a query substring."""

    def __init__(self, structs: StructGateway) -> None:
        self._structs = structs

    def execute(self, command: SearchStructsCommand) -> SearchStructsResult:
        """Filter the aggregate-type catalog by ``command.query`` and bound it.

        The comparison is case-insensitive and an empty query matches every
        struct/union. ``limit`` is clamped to :data:`MAX_SEARCH_STRUCTS_LIMIT`;
        the gateway is asked for one summary beyond the cap so ``truncated`` can be
        set when it elided further matches, and the surplus is trimmed before the
        :class:`~idamesh.domain.entities.struct_summary.StructSummary` rows are
        returned.
        """
        limit = _clamp_limit(command.limit)

        # Ask for one row past the cap: if the gateway can supply it, further
        # matches exist that the cap excludes, so ``truncated`` is set without a
        # second round-trip. The surplus row is trimmed before returning.
        rows = self._structs.list_structs(command.query, limit + 1)
        truncated = len(rows) > limit

        return SearchStructsResult(
            query=command.query,
            matches=tuple(rows[:limit]),
            truncated=truncated,
        )


def _clamp_limit(limit: int) -> int:
    """Bound a requested ``limit`` to ``[0, MAX_SEARCH_STRUCTS_LIMIT]``.

    A negative request degenerates to zero (no matches returned, though a lone
    over-the-cap probe still flags ``truncated`` when structs exist); an oversized
    request is capped at :data:`MAX_SEARCH_STRUCTS_LIMIT` so a client cannot force
    an unbounded enumeration payload.
    """
    if limit < 0:
        return 0
    if limit > MAX_SEARCH_STRUCTS_LIMIT:
        return MAX_SEARCH_STRUCTS_LIMIT
    return limit
