"""The list_globals use-case."""

from __future__ import annotations

from idamesh.application.dto.globals import ListGlobalsCommand, ListGlobalsResult
from idamesh.domain.ports.globals import GlobalRepository
from idamesh.domain.values.pagination import PageRequest


class ListGlobalsUseCase:
    """Enumerate named globals as a bounded, address-ordered page."""

    def __init__(self, globals_repo: GlobalRepository) -> None:
        self._globals = globals_repo

    def execute(self, command: ListGlobalsCommand) -> ListGlobalsResult:
        request = PageRequest.of(command.offset, command.count).clamp()
        page = self._globals.list(request)
        return ListGlobalsResult(page=page)
