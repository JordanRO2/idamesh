"""The instruction gateway port: create an instruction at an address.

Backs the ``define_code`` tool. :meth:`define_code` decodes the raw bytes at an
effective address into a single instruction, letting the analyzer determine the
instruction's length, and returns that length in bytes so the caller can report
how much was consumed. Bytes that do not decode into a valid instruction, or an
address the database refuses to convert to code, raise a domain error the caller
surfaces as an ``isError`` result. The SDK-level ``create_insn`` is the adapter's
job; this port only fixes the contract.
"""

from __future__ import annotations

from typing import Protocol

from idamesh.domain.values.address import Address


class InstructionGateway(Protocol):
    """Write-side creation of an instruction at an address."""

    def define_code(self, ea: Address) -> int:
        """Create an instruction at ``ea`` and return its length in bytes.

        The analyzer decodes the raw bytes at ``ea`` into one instruction and
        reports the number of bytes it occupies. Raises an error (surfaced by the
        caller as an ``isError`` result) when the bytes at ``ea`` do not form a
        valid instruction or the address cannot be converted to code.
        """
        ...
