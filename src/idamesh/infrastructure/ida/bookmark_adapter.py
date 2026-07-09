"""IDA adapter implementing :class:`~idamesh.domain.ports.bookmark.BookmarkGateway`.

Backs the ``add_bookmark`` tool. :meth:`add` records a marked position through the
classic, headless-safe marked-position table (``ida_idc.mark_position`` /
``get_marked_pos``): it scans the slot table so a re-mark of an already-bookmarked
address reuses that slot (refreshing its description), otherwise it claims the first
free slot, writes the mark, and confirms the write landed by reading the slot back.
An exhausted slot table, or a write the SDK silently drops, raises — surfaced by the
application as an ``isError`` result. All ``ida_*`` imports are performed lazily
inside the methods so this module loads without IDA present.
"""

from __future__ import annotations

from idamesh.domain.values.address import Address

#: Number of marked-position slots scanned when reusing or claiming one. The
#: marked-position table is 1-based; this bound mirrors the classic ``MAXMARK``
#: capacity, past which the table is treated as full.
_MAX_SLOTS = 1024


class IdaBookmarkGateway:
    """:class:`~idamesh.domain.ports.bookmark.BookmarkGateway` over the IDA SDK."""

    def add(self, ea: Address, description: str) -> int:
        """Add or update the bookmark at ``ea``; return its slot index.

        The slot table is scanned once: if a slot already marks ``ea`` it is
        reused and its description refreshed; otherwise the lowest free slot (one
        whose stored address is ``BADADDR``) is claimed. The chosen slot is then
        written and read back to confirm the mark persisted. A full table, or a
        write that does not persist, raises.
        """
        # Lazy SDK imports keep this module importable without IDA present.
        import ida_idaapi
        import ida_idc

        address = int(ea)
        empty = ida_idaapi.BADADDR

        free_slot = -1
        for slot in range(1, _MAX_SLOTS + 1):
            occupant = ida_idc.get_marked_pos(slot)
            if occupant == address:
                # This address is already marked here: reuse the slot, refreshing
                # its description in place rather than consuming a new one.
                return self._write(address, slot, description)
            if free_slot < 0 and occupant == empty:
                free_slot = slot

        if free_slot < 0:
            raise ValueError(
                f"cannot bookmark {ea.hex()}: no free marked-position slot"
            )
        return self._write(address, free_slot, description)

    @staticmethod
    def _write(address: int, slot: int, description: str) -> int:
        """Write the mark into ``slot`` and confirm it persisted; return the slot."""
        import ida_idc

        # ``mark_position(ea, lnnum, x, y, slot, comment)`` stores the position;
        # the line/column coordinates are irrelevant to an address bookmark.
        ida_idc.mark_position(address, 0, 0, 0, slot, description)
        if ida_idc.get_marked_pos(slot) != address:
            raise ValueError(
                f"cannot bookmark {Address(address).hex()}: the mark did not persist"
            )
        return slot
