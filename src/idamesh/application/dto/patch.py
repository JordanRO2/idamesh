"""Command/Result DTOs for the ``patch`` and ``patch_asm`` tools.

``PatchCommand`` carries a polymorphic address selector and the raw ``bytes`` (a
hex string, whitespace tolerated) to write; ``PatchAsmCommand`` carries the
selector and one line of ``assembly`` to encode. Each result wraps the completed
:class:`~idamesh.domain.entities.patch.BytePatch` /
:class:`~idamesh.domain.entities.patch.AsmPatch`. The selector is resolved in the
use-case, which then routes the write (and, for ``patch_asm``, the assembly)
through the shared patch gateway.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.patch import AsmPatch, BytePatch


@dataclass(frozen=True)
class PatchCommand:
    """Input for ``patch``.

    ``address`` is a polymorphic selector resolved to the write location; ``bytes``
    is the replacement data as a hexadecimal string (whitespace between octets is
    tolerated, e.g. ``"90 90"`` or ``"9090"``).
    """

    address: str
    bytes: str


@dataclass(frozen=True)
class PatchResult:
    """Output for ``patch`` — the completed raw-byte patch."""

    patch: BytePatch


@dataclass(frozen=True)
class PatchAsmCommand:
    """Input for ``patch_asm``.

    ``address`` is a polymorphic selector resolved to the write location;
    ``assembly`` is a single instruction in the database's architecture syntax to
    assemble and patch (e.g. ``"jmp 0x401000"`` or ``"nop"``).
    """

    address: str
    assembly: str


@dataclass(frozen=True)
class PatchAsmResult:
    """Output for ``patch_asm`` — the completed assemble-and-patch."""

    patch: AsmPatch
