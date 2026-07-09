"""The instruction-decode gateway port: decode a whole function to the pure model.

Backs the intra-procedural dataflow / taint / stack-string tools. The single
adapter behind this port walks the instructions of the function containing an
address and lowers each into the pure
:class:`~idamesh.domain.entities.decoded_instruction.DecodedInstruction` model, so
the algorithm services can run over a real binary while staying IDA-free and
unit-testable on synthetic sequences. The SDK-level decoding (``ida_ua`` /
``ida_idp``) is the adapter's job; this port only fixes the contract.

**Frozen contract.** The dataflow and taint work consumes this port and the
decoded model unchanged — read, never edit.
"""

from __future__ import annotations

from typing import List, Protocol

from idamesh.domain.entities.decoded_instruction import DecodedInstruction
from idamesh.domain.values.address import Address


class InstructionDecodeGateway(Protocol):
    """Decode the instructions of a function into the pure decoded model."""

    def decode_function(self, ea: Address) -> List[DecodedInstruction]:
        """Decode every instruction of the function containing ``ea``.

        Returns the function's instructions in ascending address order, each
        lowered into a :class:`DecodedInstruction`. An address in no function, or
        a database that cannot be read, raises a domain error the caller surfaces
        as an ``isError`` result. A function with no decodable instructions yields
        an empty list — a valid (sparse) result, not an error.
        """
        ...
