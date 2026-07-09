"""Catalog registration and wire-shape projection for ``search_text``.

The ``TextMatchView`` / ``SearchTextView`` ``TypedDict``s give the schema compiler
an object-rooted ``outputSchema``; :func:`search_text_view` renders each matched
listing line into that flat shape (address as ``0x`` hex). The field names mirror
the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, TypedDict

from idamesh.application.contexts.search_text import SearchTextUseCase
from idamesh.application.dto.search_text import (
    DEFAULT_SEARCH_TEXT_LIMIT,
    SearchTextCommand,
    SearchTextResult,
)
from idamesh.domain.entities.text_match import TextMatch
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class TextMatchView(TypedDict):
    """One matched disassembly line in a ``search_text`` result."""

    address: str
    line: str


class SearchTextView(TypedDict):
    """The listing lines whose rendered text matched ``text``."""

    text: str
    matches: List[TextMatchView]
    truncated: bool


def text_match_view(match: TextMatch) -> TextMatchView:
    """Project one :class:`TextMatch` into its wire shape."""
    return TextMatchView(address=match.address.hex(), line=match.line)


def search_text_view(result: SearchTextResult) -> SearchTextView:
    """Project a ``search_text`` result into its wire shape."""
    return SearchTextView(
        text=result.text,
        matches=[text_match_view(match) for match in result.matches],
        truncated=result.truncated,
    )


def register_search_text(
    registry: Registry,
    *,
    search_text_use_case: SearchTextUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``search_text`` against the listing-search use-case."""

    @registry.tool(name="search_text")
    def search_text(
        text: str, limit: int = DEFAULT_SEARCH_TEXT_LIMIT
    ) -> SearchTextView:
        """Search the rendered disassembly listing for a substring. Each defined
        item's line is rendered to plain text (control tags stripped) and tested
        for a case-insensitive match against ``text``. ``limit`` caps how many
        matches are returned (clamped to a server maximum). The result echoes the
        query ``text`` and lists each match's ``address`` (``0x`` hex) and the
        matching ``line``, with ``truncated`` set when the cap elided further
        matches. Read-only."""
        command = SearchTextCommand(text=text, limit=limit)
        result = run_use_case(
            executor, lambda: search_text_use_case.execute(command)
        )
        return search_text_view(result)
