"""The imports use-case."""

from __future__ import annotations

from idamesh.application.dto.imports import ListImportsCommand, ListImportsResult
from idamesh.domain.ports.imports import ImportRepository
from idamesh.domain.values.pagination import PageRequest


class ListImportsUseCase:
    """Enumerate imported symbols as a bounded, module-grouped page."""

    def __init__(self, imports_repo: ImportRepository) -> None:
        self._imports = imports_repo

    def execute(self, command: ListImportsCommand) -> ListImportsResult:
        """Clamp the slice request and return the corresponding page of imports."""
        request = PageRequest.of(command.offset, command.count).clamp()
        page = self._imports.list(request)
        return ListImportsResult(page=page)
