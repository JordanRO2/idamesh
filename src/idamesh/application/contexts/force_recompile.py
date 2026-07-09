"""The ``force_recompile`` use-case: flush a function's decompiler cache.

Resolves the polymorphic selector against the database gateway (mirroring the read
tools), then routes the cache invalidation through the
:class:`~idamesh.domain.ports.recompile.RecompileGateway`, which drops the stale
decompilation for the enclosing function. The selector resolution and result
assembly are the application's; the SDK-level cache clear is the gateway's.
"""

from __future__ import annotations

from idamesh.application.dto.force_recompile import (
    ForceRecompileCommand,
    ForceRecompileResult,
)
from idamesh.domain.entities.recompilation import Recompilation
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.recompile import RecompileGateway
from idamesh.domain.values.address import Selector


class ForceRecompileUseCase:
    """Resolve a selector and invalidate the decompiler cache for its function."""

    def __init__(
        self, recompiler: RecompileGateway, database: DatabaseGateway
    ) -> None:
        self._recompiler = recompiler
        self._database = database

    def execute(
        self, command: ForceRecompileCommand
    ) -> ForceRecompileResult:
        """Resolve ``command.address`` and flush its function's decompilation.

        The selector is resolved against the database gateway, then the recompile
        gateway drops the cached ``cfunc`` for the enclosing function. The completed
        invalidation is wrapped as a
        :class:`~idamesh.domain.entities.recompilation.Recompilation`. An address in
        no function, an unavailable decompiler, or an unresolvable address surfaces
        as an error the interface layer renders as an ``isError`` result.
        """
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        self._recompiler.recompile(ea)
        recompilation = Recompilation(address=ea)
        return ForceRecompileResult(recompilation=recompilation)
