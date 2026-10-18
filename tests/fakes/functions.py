"""A containment-only fake ``FunctionRepository`` shared by use-case tests."""

from __future__ import annotations

from idamesh.domain.entities.function import Function
from idamesh.domain.values.address import Address


class FakeContainingFunctions:
    """Maps an address to its owning function for ``get_containing``.

    ``owners`` maps an interior address to its function entry; any other address
    owns itself, except those in ``no_function``, which lie inside no function.
    """

    def __init__(
        self,
        owners: dict[int, int] | None = None,
        no_function: set[int] | None = None,
    ) -> None:
        self._owners = owners or {}
        self._no_function = no_function or set()

    def get_containing(self, ea: Address) -> Function | None:
        if int(ea) in self._no_function:
            return None
        entry = self._owners.get(int(ea), int(ea))
        return Function(ea=Address(entry), name=f"sub_{entry:x}", size=0x100)
