"""Catalog registration and wire-shape projection for ``find_dangerous_callers``.

The ``DangerousCallerView`` / ``DangerousApiMatchView`` / ``...View``
``TypedDict``s give the schema compiler an object-rooted ``outputSchema``;
:func:`find_dangerous_callers_view` renders each dangerous import and its call
sites into that nested shape (addresses as ``0x`` hex). The field names mirror
the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, Optional, TypedDict

from idamesh.application.contexts.find_dangerous_callers import (
    FindDangerousCallersUseCase,
)
from idamesh.application.dto.find_dangerous_callers import (
    DEFAULT_CALLER_LIMIT,
    FindDangerousCallersCommand,
    FindDangerousCallersResult,
)
from idamesh.domain.entities.dangerous_caller import (
    DangerousApiMatch,
    DangerousCaller,
)
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class DangerousCallerView(TypedDict):
    """One call site of a dangerous API and its enclosing function."""

    address: str
    function: Optional[str]


class DangerousApiMatchView(TypedDict):
    """A dangerous API and every call site that reaches it."""

    api: str
    callers: List[DangerousCallerView]


class FindDangerousCallersView(TypedDict):
    """The dangerous imports called in the image and their call sites."""

    matches: List[DangerousApiMatchView]
    truncated: bool


def dangerous_caller_view(caller: DangerousCaller) -> DangerousCallerView:
    """Project one :class:`DangerousCaller` into its wire shape (address ``0x`` hex)."""
    return DangerousCallerView(
        address=caller.address.hex(),
        function=caller.function,
    )


def dangerous_api_match_view(match: DangerousApiMatch) -> DangerousApiMatchView:
    """Project one :class:`DangerousApiMatch` into its wire shape."""
    return DangerousApiMatchView(
        api=match.api,
        callers=[dangerous_caller_view(caller) for caller in match.callers],
    )


def find_dangerous_callers_view(
    result: FindDangerousCallersResult,
) -> FindDangerousCallersView:
    """Project a ``find_dangerous_callers`` result into its wire shape."""
    return FindDangerousCallersView(
        matches=[dangerous_api_match_view(match) for match in result.matches],
        truncated=result.truncated,
    )


def register_find_dangerous_callers(
    registry: Registry,
    *,
    find_dangerous_callers_use_case: FindDangerousCallersUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``find_dangerous_callers`` against the dangerous-callsite use-case."""

    @registry.tool(name="find_dangerous_callers")
    def find_dangerous_callers(
        limit: int = DEFAULT_CALLER_LIMIT,
    ) -> FindDangerousCallersView:
        """List the dangerous imported APIs the image calls and where it calls them.

        Matches the module's imports against a classification of historically
        dangerous C-runtime and OS functions — the unbounded string copies
        (``strcpy`` / ``strcat`` / ``gets`` / ``sprintf`` …), the raw memory
        moves, the format-string sinks (``printf`` family), the input parsers
        (``scanf`` family), and the command launchers (``system`` / ``exec*`` /
        ``popen`` …) — and, for each one imported, collects every call site: its
        ``address`` (``0x`` hex) and the enclosing ``function`` name. Results are
        grouped under each ``api``; ``limit`` caps the total call sites returned
        (clamped to a server maximum) and ``truncated`` is set when the cap
        elided further sites. Read-only."""
        command = FindDangerousCallersCommand(limit=limit)
        result = run_use_case(
            executor, lambda: find_dangerous_callers_use_case.execute(command)
        )
        return find_dangerous_callers_view(result)
