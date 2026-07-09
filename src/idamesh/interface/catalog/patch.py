"""Catalog registration and wire-shape projection for ``patch`` (mutating).

The ``PatchView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`patch_view` renders the completed write into that flat
shape (address as ``0x`` hex, ``ok`` always true on success). The tool is marked
``@registry.mutating`` so its advertised ``readOnlyHint`` is ``false``. The field
names mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.patch import PatchUseCase
from idamesh.application.dto.patch import PatchCommand
from idamesh.domain.entities.patch import BytePatch
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class PatchView(TypedDict):
    """The outcome of one ``patch`` call."""

    address: str
    size: int
    ok: bool


def patch_view(patch: BytePatch) -> PatchView:
    """Project a :class:`BytePatch` into its wire shape."""
    return PatchView(
        address=patch.address.hex(),
        size=patch.size,
        ok=True,
    )


def register_patch(
    registry: Registry,
    *,
    patch_use_case: PatchUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``patch`` against the patch use-case (a mutating tool)."""

    @registry.tool(name="patch")
    @registry.mutating
    def patch(address: str, bytes: str) -> PatchView:
        """Overwrite the raw bytes at ``address`` with ``bytes``. The ``address``
        may be a hexadecimal literal (``0x…``), a decimal literal, or a symbol
        name; it is resolved first. ``bytes`` is the replacement data as a
        hexadecimal string, with whitespace between octets tolerated (``"90 90"``
        and ``"9090"`` are equivalent). The result reports the resolved ``address``
        (``0x`` hex), the ``size`` in bytes written, and ``ok``. This modifies the
        database. An empty or malformed hex payload, or an unresolvable/unwritable
        address, yields an error result rather than failing the protocol
        request."""
        command = PatchCommand(address=address, bytes=bytes)
        result = run_mutation(
            executor, lambda: patch_use_case.execute(command)
        )
        return patch_view(result.patch)
