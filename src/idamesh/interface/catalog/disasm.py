"""Catalog registration and wire-shape projection for ``disasm``.

The ``DisasmLineView`` / ``DisasmView`` ``TypedDict``s give the schema compiler
an object-rooted ``outputSchema``; :func:`disasm_view` renders the resolved
anchor and its instruction listing into that flat shape (addresses as ``0x``
hex, opcode bytes as a hex string). The field names mirror the interoperability
contract; the projection is ours.
"""

from __future__ import annotations

from typing import List, TypedDict

from idamesh.application.contexts.disasm import DisasmUseCase
from idamesh.application.dto.disasm import (
    DEFAULT_DISASM_COUNT,
    DisasmCommand,
    DisasmResult,
)
from idamesh.domain.entities.disasm import DisasmLine
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.mcp.registry import Registry


class DisasmLineView(TypedDict):
    """One rendered instruction row in a ``disasm`` listing."""

    addr: str
    bytes: str
    text: str


class DisasmView(TypedDict):
    """A bounded instruction listing rooted at ``address``."""

    address: str
    instructions: List[DisasmLineView]
    returned: int
    truncated: bool


def disasm_line_view(line: DisasmLine) -> DisasmLineView:
    """Project one :class:`DisasmLine` into its wire shape."""
    return DisasmLineView(
        addr=line.ea.hex(),
        bytes=line.raw.hex(),
        text=line.text,
    )


def disasm_view(result: DisasmResult) -> DisasmView:
    """Project a ``disasm`` result into its wire shape."""
    instructions = [disasm_line_view(line) for line in result.lines]
    return DisasmView(
        address=result.address.hex(),
        instructions=instructions,
        returned=len(instructions),
        truncated=result.truncated,
    )


def register_disasm(
    registry: Registry,
    *,
    disasm_use_case: DisasmUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``disasm`` against the disassembly use-case."""

    @registry.tool(name="disasm")
    def disasm(address: str, count: int = DEFAULT_DISASM_COUNT) -> DisasmView:
        """Return a bounded linear disassembly starting at ``address``. The
        ``address`` may be a hexadecimal literal (``0x…``), a decimal literal,
        or a symbol name; it is resolved to the first instruction listed.
        ``count`` bounds how many instructions are rendered and is clamped to a
        server maximum. Each row carries its ``addr``, the opcode ``bytes`` as a
        hex string, and the rendered instruction ``text``. The result reports
        how many instructions were ``returned`` and a ``truncated`` flag. An
        out-of-range or unresolvable address yields an error result rather than
        failing the protocol request."""
        command = DisasmCommand(address=address, count=count)
        result = run_use_case(executor, lambda: disasm_use_case.execute(command))
        return disasm_view(result)
