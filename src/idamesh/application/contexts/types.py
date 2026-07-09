"""The type tool use-cases: ``type_query`` and ``type_inspect``.

Both program against the :class:`~idamesh.domain.ports.types.TypeGateway`.
``type_query`` bounds the requested ``limit`` to a server maximum, asks the
gateway for one extra match than requested to decide the ``truncated`` flag
without a second round-trip, and returns the trimmed hits. ``type_inspect``
fetches one type by name and raises when the catalog has no such type, so the
interface layer renders an unknown name as an ``isError`` result. No SDK or
endianness logic lives here — the gateway supplies the type records.
"""

from __future__ import annotations

from idamesh.application.dto.types import (
    MAX_TYPE_QUERY_LIMIT,
    TypeInspectCommand,
    TypeInspectResult,
    TypeQueryCommand,
    TypeQueryResult,
)
from idamesh.domain.ports.types import TypeGateway


def _clamp_limit(limit: int) -> int:
    """Bound a requested ``limit`` to ``[0, MAX_TYPE_QUERY_LIMIT]``.

    A negative request degenerates to zero (no matches returned); an oversized
    request is capped at :data:`MAX_TYPE_QUERY_LIMIT` so a client cannot force an
    unbounded enumeration payload.
    """
    if limit < 0:
        return 0
    if limit > MAX_TYPE_QUERY_LIMIT:
        return MAX_TYPE_QUERY_LIMIT
    return limit


class TypeQueryUseCase:
    """List named types whose name contains a query substring."""

    def __init__(self, types: TypeGateway) -> None:
        self._types = types

    def execute(self, command: TypeQueryCommand) -> TypeQueryResult:
        """Filter the type catalog by ``command.query`` and bound the result.

        The comparison is case-insensitive and an empty query matches every named
        type. ``limit`` is clamped to :data:`MAX_TYPE_QUERY_LIMIT`; the gateway is
        asked for one match beyond the cap so ``truncated`` can be set when it
        elided further matches, and the surplus is trimmed before returning. Each
        surviving type is projected to name/kind/size by the interface layer.
        """
        limit = _clamp_limit(command.limit)
        # One match beyond the cap lets us detect an elided remainder in a single
        # round-trip without a follow-up count query.
        fetched = self._types.list_types(command.query, limit + 1)
        truncated = len(fetched) > limit
        matches = tuple(fetched[:limit])
        return TypeQueryResult(
            query=command.query,
            matches=matches,
            truncated=truncated,
        )


class TypeInspectUseCase:
    """Inspect one named type's kind, size, and member layout."""

    def __init__(self, types: TypeGateway) -> None:
        self._types = types

    def execute(self, command: TypeInspectCommand) -> TypeInspectResult:
        """Resolve ``command.name`` to a type and return its full definition.

        The gateway looks the name up in the local type catalog; a name no type
        binds to raises a ``ValueError`` the interface layer renders as an
        ``isError`` result. On success the resolved
        :class:`~idamesh.domain.entities.type_info.TypeInfo` — member layout
        included for aggregates — is returned unchanged.
        """
        type_info = self._types.get_type(command.name)
        if type_info is None:
            raise ValueError(f"unknown type: {command.name!r}")
        return TypeInspectResult(type_info=type_info)
