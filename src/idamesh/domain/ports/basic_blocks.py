"""The basic-block gateway port: recover a function's control-flow graph.

A single method, :meth:`BasicBlockGateway.blocks`, returns the basic blocks of
the function owning an address, each carrying its span and its successor entries.
Both ``basic_blocks`` (which surfaces the blocks directly) and ``func_profile``
(which counts them) program against this port; infrastructure supplies the adapter
over the SDK's flow-chart primitive.
"""

from __future__ import annotations

from typing import List, Protocol

from idamesh.domain.entities.basic_block import BasicBlock
from idamesh.domain.values.address import Address


class BasicBlockGateway(Protocol):
    """Control-flow basic-block recovery over the open database."""

    def blocks(self, ea: Address) -> List[BasicBlock]:
        """Return the basic blocks of the function containing ``ea``.

        Each block reports its half-open ``[start, end)`` span and the start
        addresses of its successors. An address inside no function surfaces as
        the adapter's error, which the interface layer renders as an ``isError``
        result rather than a protocol fault.
        """
        ...
