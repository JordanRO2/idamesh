"""Catalog registration and wire-shape projection for ``patch_asm`` (mutating).

The ``PatchAsmView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`patch_asm_view` renders the completed assemble-and-write
into that flat shape (address as ``0x`` hex, the encoded bytes as a lowercase hex
string, ``ok`` always true on success). The tool is marked ``@registry.mutating``
so its advertised ``readOnlyHint`` is ``false``. The field names mirror the
interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.patch import PatchAsmUseCase
from idamesh.application.dto.patch import PatchAsmCommand
from idamesh.domain.entities.patch import AsmPatch
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class PatchAsmView(TypedDict):
    """The outcome of one ``patch_asm`` call."""

    address: str
    bytes: str
    size: int
    ok: bool


def patch_asm_view(patch: AsmPatch) -> PatchAsmView:
    """Project an :class:`AsmPatch` into its wire shape."""
    return PatchAsmView(
        address=patch.address.hex(),
        bytes=patch.data.hex(),
        size=patch.size,
        ok=True,
    )


def register_patch_asm(
    registry: Registry,
    *,
    patch_asm_use_case: PatchAsmUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``patch_asm`` against the patch-asm use-case (a mutating tool)."""

    @registry.tool(name="patch_asm")
    @registry.mutating
    def patch_asm(address: str, assembly: str) -> PatchAsmView:
        """Assemble the single instruction ``assembly`` and patch it at
        ``address``. The ``address`` may be a hexadecimal literal (``0x…``), a
        decimal literal, or a symbol name; it is resolved first. ``assembly`` is
        one line in the database architecture's syntax (e.g. ``"jmp 0x401000"`` or
        ``"nop"``), encoded by IDA's native assembler as if placed at the resolved
        address and written there. The result reports the resolved ``address``
        (``0x`` hex), the encoded ``bytes`` as a lowercase hex string, the ``size``
        written, and ``ok``. This modifies the database. Text the architecture
        cannot assemble, or an unresolvable/unwritable address, yields an error
        result rather than failing the protocol request."""
        command = PatchAsmCommand(address=address, assembly=assembly)
        result = run_mutation(
            executor, lambda: patch_asm_use_case.execute(command)
        )
        return patch_asm_view(result.patch)
