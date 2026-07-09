"""IDA adapter implementing :class:`ListingSearchGateway`.

Walks the defined items of the image in address order, renders each disassembly
line to plain text (``ida_lines.generate_disasm_line`` + ``ida_lines.tag_remove``),
and collects the lines whose text contains the query substring (case-insensitive),
up to the requested limit. All ``ida_*`` imports are performed lazily inside the
method so this module loads without IDA present.
"""

from __future__ import annotations

from typing import List

from idamesh.domain.entities.text_match import TextMatch
from idamesh.domain.values.address import Address


class IdaListingSearchGateway:
    """:class:`~idamesh.domain.ports.listing_search.ListingSearchGateway` over the IDA SDK."""

    def search(self, text: str, limit: int) -> List[TextMatch]:
        if limit <= 0:
            return []

        # Lazy SDK imports keep this module importable without IDA present.
        import ida_lines
        import ida_segment
        import idautils

        # Compare against a lowercased needle so the substring test is
        # case-insensitive without re-lowering the query per line.
        needle = text.lower()
        matches: List[TextMatch] = []

        for seg_index in range(ida_segment.get_segm_qty()):
            segment = ida_segment.getnseg(seg_index)
            if segment is None:
                continue

            # Walk the defined items (heads) of each segment in address order.
            for head in idautils.Heads(int(segment.start_ea), int(segment.end_ea)):
                rendered = ida_lines.generate_disasm_line(head, 0)
                line = ida_lines.tag_remove(rendered) if rendered else ""
                if needle not in line.lower():
                    continue

                try:
                    address = Address(int(head))
                except ValueError:
                    # Head outside the representable address range: skip it
                    # rather than abort the whole walk.
                    continue

                matches.append(TextMatch(address=address, line=line))
                if len(matches) >= limit:
                    return matches

        return matches
