"""The :class:`DisasmLine` entity — one rendered instruction in a listing.

A disassembly line pairs an address with the instruction text IDA renders there
(mnemonic + operands, control tags already stripped) and the raw opcode bytes
that decode to it. The address/text pairing is the interoperability contract a
client reads; carrying the raw bytes alongside is our choice so a caller can
verify or re-encode without a second round-trip.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class DisasmLine:
    """A single disassembled instruction: address, rendered text, and bytes."""

    ea: Address
    text: str
    raw: bytes = b""

    @property
    def size(self) -> int:
        """Length in bytes of the instruction that decodes at :attr:`ea`."""
        return len(self.raw)
