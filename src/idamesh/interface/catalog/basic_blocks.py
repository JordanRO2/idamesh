"""Catalog registration and wire-shape projection for ``basic_blocks``.

The ``BasicBlockView`` / ``BasicBlocksView`` ``TypedDict``s give the schema
compiler an object-rooted ``outputSchema``; :func:`basic_blocks_view` renders the
resolved function and its control-flow blocks into that flat shape (addresses as
``0x`` hex, successors as a list of start addresses). The field names mirror the
interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, TypedDict

from idamesh.application.contexts.basic_blocks import BasicBlocksUseCase
from idamesh.application.dto.basic_blocks import (
    BasicBlocksCommand,
    BasicBlocksResult,
)
from idamesh.domain.entities.basic_block import BasicBlock
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class BasicBlockView(TypedDict):
    """One control-flow basic block in a ``basic_blocks`` result."""

    start: str
    end: str
    successors: List[str]


class BasicBlocksView(TypedDict):
    """The control-flow basic blocks of one resolved function ``func``."""

    func: str
    blocks: List[BasicBlockView]
    truncated: bool


def basic_block_view(block: BasicBlock) -> BasicBlockView:
    """Project one :class:`BasicBlock` into its wire shape."""
    return BasicBlockView(
        start=block.start.hex(),
        end=block.end.hex(),
        successors=[succ.hex() for succ in block.successors],
    )


def basic_blocks_view(result: BasicBlocksResult) -> BasicBlocksView:
    """Project a ``basic_blocks`` result into its wire shape."""
    return BasicBlocksView(
        func=result.func.hex(),
        blocks=[basic_block_view(block) for block in result.blocks],
        truncated=result.truncated,
    )


def register_basic_blocks(
    registry: Registry,
    *,
    basic_blocks_use_case: BasicBlocksUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``basic_blocks`` against the control-flow-block use-case."""

    @registry.tool(name="basic_blocks")
    def basic_blocks(address: str) -> BasicBlocksView:
        """List the control-flow basic blocks of the function at or containing
        ``address``. The ``address`` may be a hexadecimal literal (``0x…``), a
        decimal literal, or a symbol name; it is resolved and mapped to its
        owning function first. Each block reports its ``start`` and ``end`` (a
        half-open span) and the ``successors`` it may branch to, as their start
        addresses. The reply is capped at a server maximum, with ``truncated``
        set when the cap elided blocks. An out-of-range, unresolvable, or
        out-of-function address yields an error result rather than failing the
        protocol request."""
        command = BasicBlocksCommand(address=address)
        result = run_use_case(
            executor, lambda: basic_blocks_use_case.execute(command)
        )
        return basic_blocks_view(result)
