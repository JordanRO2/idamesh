"""IDA adapter implementing :class:`~idamesh.domain.ports.operand.OperandGateway`.

Backs the ``set_op_type`` tool. Each supported display ``kind`` maps to one
``ida_bytes`` operand-tagging primitive (``op_hex`` / ``op_dec`` / ``op_oct`` /
``op_bin`` / ``op_chr``) or, for offsets, ``ida_offset.op_plain_offset`` (a plain
offset from the image base); the chosen primitive is applied to operand ``n`` of
the instruction at the address. The requested ``kind`` is validated *before* any
SDK call, so an unknown kind is a clean domain error even with IDA absent; a
primitive the database refuses also raises — both surfaced by the application as an
``isError`` result. All ``ida_*`` imports are performed lazily inside the method so
this module loads without IDA present.
"""

from __future__ import annotations

from typing import Dict

from idamesh.domain.values.address import Address

#: Display kinds accepted for an operand, canonicalized to the ``ida_bytes``
#: primitive that installs each one. Reproduced as interoperability facts; a kind
#: outside this set (offsets excepted, handled separately) is refused.
_NUMERIC_KINDS: Dict[str, str] = {
    "hex": "op_hex",
    "dec": "op_dec",
    "oct": "op_oct",
    "bin": "op_bin",
    "char": "op_chr",
    "chr": "op_chr",
}


class IdaOperandGateway:
    """:class:`~idamesh.domain.ports.operand.OperandGateway` over the IDA SDK."""

    def set_op_type(self, ea: Address, operand: int, kind: str) -> str:
        """Apply display ``kind`` to operand ``operand`` at ``ea``; return the label.

        A numeric base routes to the matching ``ida_bytes`` primitive; ``"offset"``
        routes to ``ida_offset.op_plain_offset`` against the current image base. The
        ``kind`` is classified before any SDK import, so an unknown kind raises a
        clean :class:`ValueError` without touching IDA; a falsey return from the
        chosen primitive means the operand could not be tagged and also raises.
        """
        address = int(ea)
        label = kind.strip().lower()

        # Reject an unknown representation before touching the SDK, so a bad kind
        # is a clean domain error even with IDA absent.
        if label not in _NUMERIC_KINDS and label != "offset":
            supported = "/".join(sorted({*_NUMERIC_KINDS, "offset"}))
            raise ValueError(
                f"unknown operand type {kind!r}; expected one of {supported}"
            )

        if label == "offset":
            # Lazy SDK imports keep this module importable without IDA present.
            import ida_nalt
            import ida_offset

            base = ida_nalt.get_imagebase()
            if not ida_offset.op_plain_offset(address, operand, base):
                raise ValueError(
                    f"cannot set operand {operand} at {ea.hex()} to an offset"
                )
            return "offset"

        # Lazy SDK import keeps this module importable without IDA present.
        import ida_bytes

        primitive = getattr(ida_bytes, _NUMERIC_KINDS[label])
        if not primitive(address, operand):
            raise ValueError(
                f"cannot set operand {operand} at {ea.hex()} to {label!r}"
            )
        return "char" if label == "chr" else label
