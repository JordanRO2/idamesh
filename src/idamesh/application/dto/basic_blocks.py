"""Command/Result DTOs for ``basic_blocks``.

The command carries the polymorphic ``address`` selector (resolved to a function);
the result echoes the resolved function anchor, the recovered blocks, and a
``truncated`` flag for when a per-call cap elided some blocks of a very large
control-flow graph.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from idamesh.domain.entities.basic_block import BasicBlock
from idamesh.domain.values.address import Address

#: Per-call ceiling on the blocks ``basic_blocks`` returns for one function. A
#: pathological function can have thousands of blocks; the cap keeps the reply
#: bounded and raises ``truncated`` when it elides some.
MAX_BASIC_BLOCKS: int = 10_000


@dataclass(frozen=True)
class BasicBlocksCommand:
    """Input for ``basic_blocks``.

    ``address`` is a polymorphic selector resolved to an address inside (or at
    the entry of) the function whose control-flow blocks are returned.
    """

    address: str


@dataclass(frozen=True)
class BasicBlocksResult:
    """Output for ``basic_blocks`` — the blocks of the function at ``func``."""

    func: Address
    blocks: Tuple[BasicBlock, ...]
    truncated: bool = False
