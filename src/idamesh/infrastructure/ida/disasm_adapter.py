"""IDA adapter implementing :class:`DisassemblyGateway`.

Walks instructions forward from the anchor address, decoding each to recover its
byte length and rendering its listing text (control tags stripped), until the
instruction count is reached or the containing segment ends. All ``ida_*``
imports are performed lazily inside the method so this module loads without IDA
present.
"""

from __future__ import annotations

from typing import List

from idamesh.domain.entities.disasm import DisasmLine
from idamesh.domain.values.address import Address


class IdaDisassemblyGateway:
    """:class:`~idamesh.domain.ports.disasm.DisassemblyGateway` over the IDA SDK."""

    def disassemble(self, ea: Address, count: int) -> List[DisasmLine]:
        if count <= 0:
            return []

        import ida_bytes
        import ida_lines
        import ida_segment
        import ida_ua

        lines: List[DisasmLine] = []
        start = int(ea)
        segment = ida_segment.getseg(start)
        seg_end = int(segment.end_ea) if segment is not None else None

        cur = start
        insn = ida_ua.insn_t()
        for _ in range(count):
            if seg_end is not None and cur >= seg_end:
                # Reached the end of the containing segment: the listing is
                # complete, not merely capped.
                break

            decoded = ida_ua.decode_insn(insn, cur)
            if decoded > 0:
                size = int(decoded)
            else:
                # Not a decodable instruction (alignment/data sitting inside the
                # window): step over the defined item so the walk keeps making
                # forward progress rather than spinning on one address.
                size = int(ida_bytes.get_item_size(cur))
                if size <= 0:
                    size = 1

            try:
                anchor = Address(cur)
            except ValueError:
                # Walked past the representable address range; stop cleanly.
                break

            rendered = ida_lines.generate_disasm_line(cur, 0)
            text = ida_lines.tag_remove(rendered) if rendered else ""

            data = ida_bytes.get_bytes(cur, size)
            raw = bytes(data) if data else b""

            lines.append(DisasmLine(ea=anchor, text=text, raw=raw))
            cur += size

        return lines
