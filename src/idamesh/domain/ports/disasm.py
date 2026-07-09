"""The disassembly gateway port: render a bounded instruction listing."""

from __future__ import annotations

from typing import List, Protocol

from idamesh.domain.entities.disasm import DisasmLine
from idamesh.domain.values.address import Address


class DisassemblyGateway(Protocol):
    """Linear disassembly starting at an address, bounded by instruction count."""

    def disassemble(self, ea: Address, count: int) -> List[DisasmLine]:
        """Render up to ``count`` instructions from ``ea`` in address order.

        Walks forward instruction by instruction from ``ea``, stopping at
        ``count`` lines or when the containing segment ends, whichever comes
        first. ``count`` is assumed already clamped to a server maximum by the
        caller.
        """
        ...
