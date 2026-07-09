"""The ``patch`` and ``patch_asm`` use-cases: write bytes at a resolved address.

Both resolve the polymorphic selector against the database gateway (mirroring the
read tools) and then route the write through the shared
:class:`~idamesh.domain.ports.patch.PatchGateway`. ``patch`` decodes the caller's
hex string into a byte buffer here in the application layer — whitespace-tolerant,
non-empty, even-length — so an obviously malformed payload fails without a database
round-trip; the gateway performs the raw write. ``patch_asm`` validates the
assembly text is non-empty, then has the gateway assemble it to machine bytes and
patches those bytes at the address. A bad payload, un-assemblable text, or an
unresolvable/unwritable address surfaces as an error the interface layer renders as
an ``isError`` result.
"""

from __future__ import annotations

from idamesh.application.dto.patch import (
    PatchAsmCommand,
    PatchAsmResult,
    PatchCommand,
    PatchResult,
)
from idamesh.domain.entities.patch import AsmPatch, BytePatch
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.patch import PatchGateway
from idamesh.domain.values.address import Selector


def _parse_hex(raw: str) -> bytes:
    """Decode a whitespace-tolerant hex string into bytes, else raise.

    Interior whitespace between octets is stripped, so ``"90 90"`` and ``"9090"``
    both decode. An empty payload, an odd number of hex digits, or a non-hex
    character is rejected before the gateway is touched.
    """
    if not isinstance(raw, str):
        raise ValueError(f"bytes must be a string, got {type(raw).__name__}")
    compact = "".join(raw.split())
    if not compact:
        raise ValueError("bytes must not be empty")
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise ValueError(f"invalid hex bytes: {raw!r}") from exc


def _require_asm(text: str) -> str:
    """Return ``text`` if it is a non-empty, non-blank string, else raise."""
    if not isinstance(text, str):
        raise ValueError(f"assembly must be a string, got {type(text).__name__}")
    stripped = text.strip()
    if not stripped:
        raise ValueError("assembly must not be empty")
    return stripped


class PatchUseCase:
    """Resolve a selector and overwrite the bytes at the item there."""

    def __init__(self, patch: PatchGateway, database: DatabaseGateway) -> None:
        self._patch = patch
        self._database = database

    def execute(self, command: PatchCommand) -> PatchResult:
        """Resolve ``command.address`` and write ``command.bytes`` at it.

        The hex payload is decoded and checked non-empty, the selector is resolved
        against the database gateway, then the patch gateway writes the buffer and
        reports the count landed. The completed change is wrapped as a
        :class:`~idamesh.domain.entities.patch.BytePatch`. A malformed payload or an
        unresolvable/unwritable address surfaces as an error the interface layer
        renders as an ``isError`` result.
        """
        data = _parse_hex(command.bytes)
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        written = self._patch.patch_bytes(ea, data)
        patch = BytePatch(address=ea, size=written)
        return PatchResult(patch=patch)


class PatchAsmUseCase:
    """Resolve a selector, assemble one instruction, and patch it there."""

    def __init__(self, patch: PatchGateway, database: DatabaseGateway) -> None:
        self._patch = patch
        self._database = database

    def execute(self, command: PatchAsmCommand) -> PatchAsmResult:
        """Resolve ``command.address`` and assemble+patch ``command.assembly``.

        The assembly text is checked non-empty, the selector is resolved against
        the database gateway, then the patch gateway assembles the instruction to
        machine bytes (encoded as if at the address) and those bytes are patched in.
        The completed change is wrapped as a
        :class:`~idamesh.domain.entities.patch.AsmPatch`. Text the architecture
        cannot assemble, or an unresolvable/unwritable address, surfaces as an error
        the interface layer renders as an ``isError`` result.
        """
        text = _require_asm(command.assembly)
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        data = self._patch.assemble(ea, text)
        written = self._patch.patch_bytes(ea, data)
        patch = AsmPatch(address=ea, data=data, size=written)
        return PatchAsmResult(patch=patch)
