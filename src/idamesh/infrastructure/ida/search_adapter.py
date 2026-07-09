"""IDA adapter implementing :class:`SearchGateway`.

Parses an IDA-style hexadecimal byte pattern (wildcards allowed) into the SDK's
binary-pattern form and scans the searchable image forward, collecting up to the
requested number of match addresses. All ``ida_*`` imports are performed lazily
inside the method so this module loads without IDA present.
"""

from __future__ import annotations

from typing import List

from idamesh.domain.values.address import Address


class IdaSearchGateway:
    """:class:`~idamesh.domain.ports.search.SearchGateway` over the IDA SDK."""

    def find_bytes(self, pattern: str, limit: int) -> List[Address]:
        if limit <= 0:
            return []

        # Lazy SDK imports keep this module importable without IDA present.
        import ida_bytes
        import ida_ida
        import ida_idaapi

        min_ea = int(ida_ida.inf_get_min_ea())
        max_ea = int(ida_ida.inf_get_max_ea())
        bad_addr = int(ida_idaapi.BADADDR)

        # Compile the IDA-style hex pattern (wildcards allowed) at radix 16. An
        # empty compiled vector means the pattern was unparseable — surface it as
        # a ValueError so the use-case renders an isError result.
        binpat = ida_bytes.compiled_binpat_vec_t()
        parsed = ida_bytes.parse_binpat_str(binpat, min_ea, pattern, 16)
        if parsed is None or parsed is False or len(binpat) == 0:
            raise ValueError(f"unparseable byte pattern: {pattern!r}")

        # Forward scan, no UI feedback and no cooperative break so the search
        # stays headless. ``BIN_SEARCH_CASE`` is a no-op for byte patterns but is
        # required by the flag word on the versions that define it.
        flags = (
            getattr(ida_bytes, "BIN_SEARCH_FORWARD", 0x01)
            | getattr(ida_bytes, "BIN_SEARCH_NOSHOW", 0x08)
            | getattr(ida_bytes, "BIN_SEARCH_NOBREAK", 0x04)
            | getattr(ida_bytes, "BIN_SEARCH_CASE", 0x00)
        )

        matches: List[Address] = []
        cursor = min_ea
        while cursor < max_ea and len(matches) < limit:
            hit = ida_bytes.bin_search(cursor, max_ea, binpat, flags)
            # Newer SDKs return ``(ea, pattern_index)``; older ones a bare ea.
            if isinstance(hit, tuple):
                hit = hit[0]
            if hit is None:
                break
            hit = int(hit)
            if hit == bad_addr:
                break
            try:
                matches.append(Address(hit))
            except ValueError:
                break
            cursor = hit + 1

        return matches
