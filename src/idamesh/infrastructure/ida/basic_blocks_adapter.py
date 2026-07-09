"""IDA adapter implementing :class:`BasicBlockGateway`.

Recovers a function's control-flow basic blocks via the SDK's flow-chart
primitive: it resolves the owning function, walks the flow chart, and maps each
node onto a :class:`~idamesh.domain.entities.basic_block.BasicBlock` carrying its
span and the start addresses of its successors. All ``ida_*`` imports are
performed lazily inside the method so this module loads without IDA present.
"""

from __future__ import annotations

from typing import List

from idamesh.domain.entities.basic_block import BasicBlock
from idamesh.domain.values.address import Address


class BasicBlockError(RuntimeError):
    """Raised when a block query anchors on an address inside no function.

    The interface layer turns this into an ``isError`` tool result rather than a
    protocol fault, mirroring how the xref and decompiler adapters report a
    missing function.
    """


class IdaBasicBlockGateway:
    """:class:`~idamesh.domain.ports.basic_blocks.BasicBlockGateway` over the IDA SDK."""

    def blocks(self, ea: Address) -> List[BasicBlock]:
        import ida_funcs
        import ida_gdl

        anchor = int(ea)
        func = ida_funcs.get_func(anchor)
        if func is None:
            raise BasicBlockError(
                f"no function contains {ea.hex()}; basic_blocks needs an "
                "address inside a function"
            )

        out: List[BasicBlock] = []
        for node in ida_gdl.FlowChart(func):
            try:
                start = Address(int(node.start_ea))
                end = Address(int(node.end_ea))
            except ValueError:
                # Skip a node whose span endpoint is the invalid sentinel.
                continue
            successors: List[Address] = []
            for succ in node.succs():
                try:
                    successors.append(Address(int(succ.start_ea)))
                except ValueError:
                    continue
            out.append(
                BasicBlock(start=start, end=end, successors=tuple(successors))
            )
        return out
