"""The ``export_funcs`` use-case.

Reuses the :class:`~idamesh.domain.ports.functions.FunctionRepository` (the same
enumeration behind ``list_funcs``), takes an ``{offset, count}`` slice, and
projects each :class:`~idamesh.domain.entities.function.Function` down to the
compact :class:`~idamesh.domain.entities.func_ref.FuncRef` (name + address) so the
result is a lightweight bulk export suitable for feeding into other tools. No new
adapter is required.
"""

from __future__ import annotations

from typing import List

from idamesh.application.dto.export_funcs import (
    ExportFuncsCommand,
    ExportFuncsResult,
)
from idamesh.domain.entities.func_ref import FuncRef
from idamesh.domain.ports.functions import FunctionRepository
from idamesh.domain.values.pagination import Page, PageRequest


class ExportFuncsUseCase:
    """Export a bounded page of functions as compact name/address references."""

    def __init__(self, functions: FunctionRepository) -> None:
        self._functions = functions

    def execute(self, command: ExportFuncsCommand) -> ExportFuncsResult:
        """Build a clamped page request, list the slice, and project to refs.

        The ``{offset, count}`` request is normalized and clamped to a server
        maximum before it reaches the repository; each returned function is mapped
        to a :class:`~idamesh.domain.entities.func_ref.FuncRef`, and the
        pagination metadata (offset, count, total, truncation, cursor) is carried
        through so a caller can stream the whole function set.
        """
        request = PageRequest.of(command.offset, command.count).clamp()
        source = self._functions.list(request)
        refs: List[FuncRef] = [
            FuncRef(address=function.ea, name=function.name)
            for function in source.items
        ]
        page: Page[FuncRef] = Page(
            items=refs,
            offset=source.offset,
            count=source.count,
            total=source.total,
            truncated=source.truncated,
            next_cursor=source.next_cursor,
        )
        return ExportFuncsResult(page=page)
