"""The disasm use-case."""

from __future__ import annotations

from idamesh.application.dto.disasm import (
    MAX_DISASM_COUNT,
    DisasmCommand,
    DisasmResult,
)
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.disasm import DisassemblyGateway
from idamesh.domain.values.address import Selector


class DisasmUseCase:
    """Resolve a selector and return a bounded disassembly listing from it.

    Uses the database gateway to resolve the polymorphic ``address`` selector,
    then the disassembly gateway to render up to the clamped instruction count.
    """

    def __init__(
        self,
        disassembly: DisassemblyGateway,
        database: DatabaseGateway,
    ) -> None:
        self._disassembly = disassembly
        self._database = database

    def execute(self, command: DisasmCommand) -> DisasmResult:
        """Resolve ``command.address``, clamp ``count``, and render the listing.

        The requested instruction budget is bounded to
        :data:`MAX_DISASM_COUNT` before it reaches the gateway, so an oversized
        request can never make the walk unbounded. Truncation is inferred from
        the returned length: a listing that exactly fills the budget means the
        walk stopped on the cap and further instructions may follow, whereas a
        short listing means it ran into a segment boundary and nothing was
        dropped.
        """
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        count = _clamp(command.count)
        lines = self._disassembly.disassemble(ea, count)
        truncated = count > 0 and len(lines) >= count
        return DisasmResult(address=ea, lines=tuple(lines), truncated=truncated)


def _clamp(count: int) -> int:
    """Bound a requested instruction count to ``[0, MAX_DISASM_COUNT]``."""
    if count < 0:
        return 0
    if count > MAX_DISASM_COUNT:
        return MAX_DISASM_COUNT
    return count
