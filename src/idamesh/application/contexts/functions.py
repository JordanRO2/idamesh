"""The list_funcs use-case."""

from __future__ import annotations

from idamesh.application.dto.functions import ListFuncsCommand, ListFuncsResult
from idamesh.domain.ports.functions import FunctionRepository
from idamesh.domain.values.pagination import PageRequest


class ListFuncsUseCase:
    """Enumerate functions as a bounded, cursor-stamped page."""

    def __init__(self, functions: FunctionRepository) -> None:
        self._functions = functions

    def execute(self, command: ListFuncsCommand) -> ListFuncsResult:
        request = PageRequest.of(command.offset, command.count).clamp()
        page = self._functions.list(request)
        return ListFuncsResult(page=page)
