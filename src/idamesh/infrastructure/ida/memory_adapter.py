"""IDA adapter implementing :class:`MemoryGateway`.

Reads raw bytes and string literals from the loaded image. Byte reads map to
``ida_bytes.get_bytes``; string reads prefer a defined literal via
``ida_bytes.get_strlit_contents`` (with the string type detected through
``ida_nalt.get_str_type``) and fall back to a bounded, terminator-aware scan when
no literal is defined at the address. The gateway returns *raw* bytes and leaves
integer/endianness interpretation to the application layer. All ``ida_*`` imports
are performed lazily inside the methods so this module loads without IDA present.
"""

from __future__ import annotations

from typing import Optional

from idamesh.domain.values.address import Address

#: Server-side ceiling on a string scan when a caller passes ``max_length=None``.
_DEFAULT_STRING_CEILING: int = 4096
#: ``get_str_type``'s "not a string" sentinel, matched defensively across builds.
_BAD_STR_TYPE: int = 0xFFFFFFFF


class IdaMemoryGateway:
    """:class:`~idamesh.domain.ports.memory.MemoryGateway` over the IDA SDK."""

    def read_bytes(self, ea: Address, size: int) -> bytes:
        # Lazy SDK import keeps this module importable without IDA present.
        import ida_bytes

        if size <= 0:
            raise ValueError(f"size must be positive, got {size}")
        address = int(ea)
        data = ida_bytes.get_bytes(address, size)
        if data is None or len(data) != size:
            raise ValueError(
                f"cannot read {size} bytes at {ea.hex()}: region is unreadable"
            )
        return bytes(data)

    def read_string(self, ea: Address, max_length: Optional[int]) -> Optional[str]:
        # Lazy SDK import keeps this module importable without IDA present.
        import ida_bytes
        import ida_nalt

        address = int(ea)
        ceiling = self._ceiling(max_length)

        # Prefer a defined string literal so the terminator/encoding are honoured.
        str_type = ida_nalt.get_str_type(address)
        if str_type is not None and 0 <= str_type != _BAD_STR_TYPE:
            raw = ida_bytes.get_strlit_contents(address, -1, str_type)
            if raw:
                return bytes(raw).decode("utf-8", errors="replace")[:ceiling]

        # Fall back to a bounded, NUL-terminated scan over mapped bytes.
        collected = bytearray()
        for offset in range(ceiling):
            here = address + offset
            if not ida_bytes.is_loaded(here):
                break
            byte = ida_bytes.get_byte(here)
            if byte == 0:
                break
            collected.append(byte)
        if not collected:
            return None
        return collected.decode("utf-8", errors="replace")

    @staticmethod
    def _ceiling(max_length: Optional[int]) -> int:
        """Resolve the effective scan ceiling, applying the server default."""
        if max_length is None or max_length <= 0:
            return _DEFAULT_STRING_CEILING
        return max_length
