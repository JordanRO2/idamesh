"""IDA adapter implementing :class:`GlobalRepository`.

Thin SDK wrapper over ``idautils.Names`` filtered to data items. Lazy ``ida_*``
imports so the module loads without IDA present. Enumeration is address-ordered
(as ``idautils.Names`` yields it); pagination is applied over the materialized
filtered stream and the page carries the total for client-side progress.

Note: ``idautils.Names`` yields every named address, so both the total and the
page are derived from a single filtering pass. For very large databases this
would be a candidate for a cached index (Phase 2's strings/name cache seam);
kept simple here since the slice's correctness contract comes first.
"""

from __future__ import annotations

from typing import List, Optional

from idamesh.domain.entities.data import Global
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import Page, PageRequest


class IdaGlobalRepository:
    """:class:`~idamesh.domain.ports.globals.GlobalRepository` over the IDA SDK."""

    def list(self, page: PageRequest) -> Page[Global]:
        request = page.clamp()
        rows = self._collect()
        total = len(rows)
        start = request.offset
        stop = start + request.count
        items = rows[start:stop]
        truncated = stop < total
        return Page(
            items=items,
            offset=start,
            count=request.count,
            total=total,
            truncated=truncated,
        )

    def count(self) -> int:
        return len(self._collect())

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _collect() -> List[Global]:
        import ida_bytes
        import ida_name
        import idautils

        # idalib does not populate the name-list index that ``idautils.Names()``
        # walks: ``get_nlist_size()`` is 0 even after full auto-analysis, so a bare
        # ``Names()`` yields nothing and every named global is missed (verified on a
        # real database: 0 rows vs. 900 named data items actually present). Build the
        # nlist on demand — cheap, and a no-op once populated. A GUI database that
        # presents an unbuilt nlist is repaired identically.
        if ida_name.get_nlist_size() == 0:
            ida_name.rebuild_nlist()

        out: List[Global] = []
        for ea, name in idautils.Names():
            flags = ida_bytes.get_full_flags(int(ea))
            if not ida_bytes.is_data(flags):
                # A named global is a data item; skip code/function labels.
                continue
            try:
                addr = Address(int(ea))
            except ValueError:
                continue
            size = _item_size(int(ea))
            out.append(
                Global(
                    ea=addr,
                    name=name or "",
                    size=size,
                    type_name=_type_name(int(ea)),
                )
            )
        return out


def _item_size(ea: int) -> int:
    try:
        import ida_bytes

        size = int(ida_bytes.get_item_size(ea))
        return size if size >= 0 else 0
    except Exception:
        return 0


def _type_name(ea: int) -> Optional[str]:
    try:
        import idc

        declared = idc.get_type(ea)
        return declared or None
    except Exception:
        return None
