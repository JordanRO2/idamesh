"""IDA adapter implementing :class:`~idamesh.domain.ports.instruction.InstructionGateway`.

Backs the ``define_code`` tool. :meth:`define_code` decodes one instruction at the
address with ``ida_ua.create_insn`` and reports its length. A zero return means the
bytes there do not form a valid instruction and raises — surfaced by the application
as an ``isError`` result. All ``ida_*`` imports are performed lazily inside the
method so this module loads without IDA present.
"""

from __future__ import annotations

from idamesh.domain.values.address import Address


class IdaInstructionGateway:
    """:class:`~idamesh.domain.ports.instruction.InstructionGateway` over the SDK."""

    def define_code(self, ea: Address) -> int:
        """Create an instruction at ``ea`` and return its length in bytes.

        ``ida_ua.create_insn`` decodes the bytes at the address into one
        instruction and returns the number of bytes consumed; a zero return means
        the bytes do not decode and raises.
        """
        # Lazy SDK import keeps this module importable without IDA present.
        import ida_ua

        address = int(ea)
        length = ida_ua.create_insn(address)
        if not length:
            raise ValueError(
                f"cannot create an instruction at {ea.hex()}: the bytes there do "
                "not decode"
            )
        return int(length)
