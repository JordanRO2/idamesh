"""The ``find_regex`` use-case.

Reuses the :class:`~idamesh.domain.ports.strings.StringsRepository` (the same
materialized string set behind ``list_strings``), compiles the client's Python
regular expression once, and filters the strings by ``re.search`` in the
application layer — a *pure* filter, so no new adapter is needed. The match budget
is clamped to :data:`MAX_REGEX_LIMIT` and ``truncated`` reports when the cap
elided further matches.
"""

from __future__ import annotations

import re
from typing import List

from idamesh.application.dto.find_regex import (
    MAX_REGEX_LIMIT,
    FindRegexCommand,
    FindRegexResult,
)
from idamesh.domain.entities.string_item import StringItem
from idamesh.domain.ports.strings import StringsRepository
from idamesh.domain.values.pagination import MAX_COUNT, PageRequest


class FindRegexUseCase:
    """Filter the extracted-string set by a Python regular expression."""

    def __init__(self, strings: StringsRepository) -> None:
        self._strings = strings

    def execute(self, command: FindRegexCommand) -> FindRegexResult:
        """Compile ``command.pattern``, filter the strings, and wrap the matches.

        The pattern is compiled once (an invalid pattern surfaces as an error the
        interface layer renders as an ``isError`` result); the materialized string
        set is walked page by page and scanned with ``re.search``, matches
        accumulated up to the ``limit`` clamped to :data:`MAX_REGEX_LIMIT`.
        ``truncated`` is set when the cap stopped the scan before the string set
        was exhausted — i.e. at least one further match existed beyond the budget.
        """
        matcher = self._compile(command.pattern)
        limit = self._clamp(command.limit)

        matches: List[StringItem] = []
        truncated = False
        offset = 0
        while True:
            page = self._strings.list(PageRequest(offset=offset, count=MAX_COUNT))
            items = tuple(page.items)
            if not items:
                break
            budget_exhausted = False
            for item in items:
                if matcher.search(item.value) is None:
                    continue
                if len(matches) >= limit:
                    # A match beyond the (clamped) budget: the cap elided further
                    # matches. A zero budget is never a truncation — nothing was
                    # asked for — so the flag tracks only a positive limit.
                    truncated = limit > 0
                    budget_exhausted = True
                    break
                matches.append(item)
            if budget_exhausted:
                break
            offset += len(items)
            # A short page means the whole materialized set was consumed.
            if len(items) < MAX_COUNT:
                break

        return FindRegexResult(
            pattern=command.pattern,
            matches=tuple(matches),
            truncated=truncated,
        )

    @staticmethod
    def _compile(pattern: str) -> "re.Pattern[str]":
        """Compile the client's Python regex, normalizing failures to ``ValueError``.

        ``re`` raises ``re.error`` (not a ``ValueError``) on a malformed pattern;
        it is re-raised as a ``ValueError`` so the interface layer renders it as a
        clean ``isError`` result rather than an opaque adapter fault.
        """
        try:
            return re.compile(pattern)
        except re.error as exc:
            raise ValueError(
                f"invalid regular expression {pattern!r}: {exc}"
            ) from exc

    @staticmethod
    def _clamp(limit: int) -> int:
        """Bound the requested match budget to ``[0, MAX_REGEX_LIMIT]``."""
        if limit > MAX_REGEX_LIMIT:
            return MAX_REGEX_LIMIT
        if limit < 0:
            return 0
        return limit
