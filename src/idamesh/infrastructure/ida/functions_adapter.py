"""IDA adapter implementing :class:`FunctionRepository`.

Thin SDK wrapper over ``idautils.Functions`` / ``ida_funcs``. Lazy ``ida_*``
imports so the module loads without IDA present. Enumeration is address-ordered
(as ``idautils.Functions`` yields it); pagination is applied over that stream and
the page carries the total function count for client-side progress.
"""

from __future__ import annotations

from typing import Optional

from idamesh.domain.entities.function import Function
from idamesh.domain.values.address import INVALID_EA, Address
from idamesh.domain.values.pagination import Page, PageRequest


def _end_address(value: int) -> Optional[Address]:
    if value is None or value < 0 or value >= INVALID_EA:
        return None
    try:
        return Address(value)
    except ValueError:
        return None


class IdaFunctionRepository:
    """:class:`~idamesh.domain.ports.functions.FunctionRepository` over the IDA SDK."""

    def list(self, page: PageRequest) -> Page[Function]:
        import idautils

        request = page.clamp()
        total = self.count()
        start = request.offset
        stop = start + request.count

        items: list[Function] = []
        for index, ea in enumerate(idautils.Functions()):
            if index < start:
                continue
            if index >= stop:
                break
            built = self._build(int(ea))
            if built is not None:
                items.append(built)

        truncated = stop < total
        return Page(
            items=items,
            offset=start,
            count=request.count,
            total=total,
            truncated=truncated,
        )

    def count(self) -> int:
        import ida_funcs

        return int(ida_funcs.get_func_qty())

    def get(self, ea: Address) -> Function | None:
        import ida_funcs

        func = ida_funcs.get_func(int(ea))
        if func is None or func.start_ea != int(ea):
            return None
        return self._build(func.start_ea)

    def get_containing(self, ea: Address) -> Function | None:
        import ida_funcs

        func = ida_funcs.get_func(int(ea))
        if func is None:
            return None
        return self._build(func.start_ea)

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _build(ea: int) -> Optional[Function]:
        import ida_funcs

        func = ida_funcs.get_func(ea)
        if func is None:
            return None
        name = ida_funcs.get_func_name(ea) or ""
        end = int(func.end_ea)
        size = end - int(func.start_ea)
        if size < 0:
            size = 0
        flags = int(getattr(func, "flags", 0))
        is_library = bool(flags & ida_funcs.FUNC_LIB)
        is_thunk = bool(flags & ida_funcs.FUNC_THUNK)
        try:
            start = Address(int(func.start_ea))
        except ValueError:
            return None
        return Function(
            ea=start,
            name=name,
            size=size,
            end_ea=_end_address(end),
            flags=flags,
            is_library=is_library,
            is_thunk=is_thunk,
        )
