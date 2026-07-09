"""IDA adapter implementing :class:`ImportRepository`.

Wraps the SDK's import-table enumeration (module count, per-module symbol
callback) into a materialized, address-ordered stream that pagination slices.
All ``ida_*`` imports are performed lazily inside the methods so this module
loads without IDA present.
"""

from __future__ import annotations

from typing import List

from idamesh.domain.entities.imports import Import
from idamesh.domain.values.address import Address
from idamesh.domain.values.pagination import Page, PageRequest


class IdaImportRepository:
    """:class:`~idamesh.domain.ports.imports.ImportRepository` over the IDA SDK."""

    def list(self, page: PageRequest) -> Page[Import]:
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
    def _collect() -> List[Import]:
        """Materialize every imported symbol across all modules, in table order."""
        import ida_nalt

        out: List[Import] = []
        module_qty = ida_nalt.get_import_module_qty()
        for index in range(module_qty):
            module = ida_nalt.get_import_module_name(index) or ""

            def visit(ea: int, name: str, ordinal: int, _module: str = module) -> int:
                # enum_import_names invokes this once per symbol in the module,
                # passing three positional arguments; the bound ``_module``
                # default captures this iteration's module name. Returning a
                # truthy value keeps the enumeration going.
                try:
                    addr = Address(int(ea))
                except ValueError:
                    return True
                out.append(
                    Import(
                        ea=addr,
                        name=name or "",
                        module=_module,
                        ordinal=ordinal or None,
                    )
                )
                return True

            ida_nalt.enum_import_names(index, visit)
        return out
