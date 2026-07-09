"""Catalog registration and wire-shape projection for ``find_bytes``.

The ``ByteMatchView`` / ``FindBytesView`` ``TypedDict``s give the schema compiler
an object-rooted ``outputSchema``; :func:`find_bytes_view` renders the matched
addresses into that flat shape (addresses as ``0x`` hex). The field names mirror
the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, TypedDict

from idamesh.application.contexts.find_bytes import FindBytesUseCase
from idamesh.application.dto.find_bytes import (
    DEFAULT_MATCH_LIMIT,
    FindBytesCommand,
    FindBytesResult,
)
from idamesh.domain.entities.byte_match import ByteMatch
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class ByteMatchView(TypedDict):
    """One matched address in a ``find_bytes`` result."""

    address: str


class FindBytesView(TypedDict):
    """The addresses at which a byte ``pattern`` matched."""

    pattern: str
    matches: List[ByteMatchView]
    truncated: bool


def byte_match_view(match: ByteMatch) -> ByteMatchView:
    """Project one :class:`ByteMatch` into its wire shape (address as ``0x`` hex)."""
    return ByteMatchView(address=match.address.hex())


def find_bytes_view(result: FindBytesResult) -> FindBytesView:
    """Project a ``find_bytes`` result into its wire shape."""
    return FindBytesView(
        pattern=result.pattern,
        matches=[byte_match_view(match) for match in result.matches],
        truncated=result.truncated,
    )


def register_find_bytes(
    registry: Registry,
    *,
    find_bytes_use_case: FindBytesUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``find_bytes`` against the byte-pattern-search use-case."""

    @registry.tool(name="find_bytes")
    def find_bytes(pattern: str, limit: int = DEFAULT_MATCH_LIMIT) -> FindBytesView:
        """Search the loaded image for a byte ``pattern`` and return the
        addresses where it matches. ``pattern`` is an IDA-style hexadecimal byte
        pattern that may contain wildcards — for example ``"48 8B ?? 05"``, where
        ``??`` (or ``?``) matches any byte. ``limit`` caps how many matches are
        returned (clamped to a server maximum). The result echoes the ``pattern``
        and lists each match's ``address`` as ``0x`` hex, with ``truncated`` set
        when the cap elided further matches. An unparseable pattern yields an
        error result rather than failing the protocol request."""
        command = FindBytesCommand(pattern=pattern, limit=limit)
        result = run_use_case(
            executor, lambda: find_bytes_use_case.execute(command)
        )
        return find_bytes_view(result)
