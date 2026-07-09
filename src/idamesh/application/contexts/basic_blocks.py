"""The ``basic_blocks`` use-case.

Resolves the polymorphic ``address`` selector against the database gateway
(mirroring ``callees``), then queries the basic-block gateway for the control-flow
blocks of the owning function, capping the reply at a per-call maximum.
"""

from __future__ import annotations

from idamesh.application.dto.basic_blocks import (
    MAX_BASIC_BLOCKS,
    BasicBlocksCommand,
    BasicBlocksResult,
)
from idamesh.domain.ports.basic_blocks import BasicBlockGateway
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.values.address import Selector


class BasicBlocksUseCase:
    """Resolve a selector and return its function's control-flow basic blocks."""

    def __init__(
        self,
        blocks: BasicBlockGateway,
        database: DatabaseGateway,
    ) -> None:
        self._blocks = blocks
        self._database = database

    def execute(self, command: BasicBlocksCommand) -> BasicBlocksResult:
        """Resolve ``command.address`` and collect its function's blocks.

        The selector is resolved to a concrete address; the gateway recovers the
        owning function's flow-chart blocks. The reply is capped at
        :data:`MAX_BASIC_BLOCKS`, with ``truncated`` set when the cap elided
        blocks. An address inside no function surfaces as the gateway's error,
        which the interface layer renders as an ``isError`` result.
        """
        selector = Selector.parse(command.address)
        func = self._database.resolve(selector)
        blocks = self._blocks.blocks(func)
        kept = tuple(blocks[:MAX_BASIC_BLOCKS])
        return BasicBlocksResult(
            func=func,
            blocks=kept,
            truncated=len(blocks) > MAX_BASIC_BLOCKS,
        )
