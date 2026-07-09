"""Catalog registration and wire-shape projection for ``find_regex``.

The ``RegexMatchView`` / ``FindRegexView`` ``TypedDict``s give the schema compiler
an object-rooted ``outputSchema``; :func:`find_regex_view` renders each matched
string into that flat shape (address as ``0x`` hex, only the address and value
surfaced). The field names mirror the interoperability contract; the projection
is ours.
"""

from __future__ import annotations

from typing import List, TypedDict

from idamesh.application.contexts.find_regex import FindRegexUseCase
from idamesh.application.dto.find_regex import (
    DEFAULT_REGEX_LIMIT,
    FindRegexCommand,
    FindRegexResult,
)
from idamesh.domain.entities.string_item import StringItem
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class RegexMatchView(TypedDict):
    """One matched string in a ``find_regex`` result."""

    address: str
    value: str


class FindRegexView(TypedDict):
    """The extracted strings whose value matched ``pattern``."""

    pattern: str
    matches: List[RegexMatchView]
    truncated: bool


def regex_match_view(item: StringItem) -> RegexMatchView:
    """Project one matched :class:`StringItem` into its wire shape."""
    return RegexMatchView(address=item.address.hex(), value=item.value)


def find_regex_view(result: FindRegexResult) -> FindRegexView:
    """Project a ``find_regex`` result into its wire shape."""
    return FindRegexView(
        pattern=result.pattern,
        matches=[regex_match_view(item) for item in result.matches],
        truncated=result.truncated,
    )


def register_find_regex(
    registry: Registry,
    *,
    find_regex_use_case: FindRegexUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``find_regex`` against the regex-over-strings use-case."""

    @registry.tool(name="find_regex")
    def find_regex(pattern: str, limit: int = DEFAULT_REGEX_LIMIT) -> FindRegexView:
        """Search the strings IDA extracted from the binary for those whose value
        matches a Python regular expression. ``pattern`` is applied with
        ``re.search`` against each string's decoded value. ``limit`` caps how many
        matches are returned (clamped to a server maximum). The result echoes the
        ``pattern`` and lists each match's ``address`` (``0x`` hex) and matching
        ``value``, with ``truncated`` set when the cap elided further matches. An
        invalid regular expression yields an error result rather than failing the
        protocol request."""
        command = FindRegexCommand(pattern=pattern, limit=limit)
        result = run_use_case(
            executor, lambda: find_regex_use_case.execute(command)
        )
        return find_regex_view(result)
