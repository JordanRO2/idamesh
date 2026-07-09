"""The list_strings use-case."""

from __future__ import annotations

from idamesh.application.dto.list_strings import (
    ListStringsCommand,
    ListStringsResult,
)
from idamesh.domain.ports.strings import StringsRepository
from idamesh.domain.values.pagination import PageRequest


class ListStringsUseCase:
    """Enumerate extracted strings as a bounded, address-ordered page."""

    def __init__(self, strings: StringsRepository) -> None:
        self._strings = strings

    def execute(self, command: ListStringsCommand) -> ListStringsResult:
        """Build a clamped page request and return the matching slice.

        The ``{offset, count}`` request is normalized and clamped to a server
        maximum before it reaches the repository, which materializes the strings
        once and slices the page from the cached set.
        """
        request = PageRequest.of(command.offset, command.count).clamp()
        page = self._strings.list(request)
        return ListStringsResult(page=page)
