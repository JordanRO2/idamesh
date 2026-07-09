"""The data-definition gateway port: define a data item at an address.

Backs the ``make_data`` tool. :meth:`make_data` turns raw bytes at an effective
address into a data item — applying a parsed C type when a declaration is supplied,
otherwise creating a primitive item of the requested byte width. It reports the
type actually applied and the size the item occupies afterward, so the caller can
echo both. A declaration that will not parse, an unsupported size, or a definition
the database refuses raises a domain error the caller surfaces as an ``isError``
result. Parsing, item creation, and type application are the adapter's SDK-level
job; this port only fixes the contract.
"""

from __future__ import annotations

from typing import Protocol, Tuple

from idamesh.domain.values.address import Address


class DataDefinitionGateway(Protocol):
    """Write-side definition of a data item at an address."""

    def make_data(self, ea: Address, type: str, size: int) -> Tuple[str, int]:
        """Define a data item at ``ea``; return ``(applied_type, size)``.

        When ``type`` is a non-empty C declaration it is parsed and applied, and
        the item is sized to that type; when ``type`` is empty a primitive item of
        ``size`` bytes (1/2/4/8 → byte/word/dword/qword) is created. The returned
        ``applied_type`` names the type in force afterward (the primitive's name
        when none was supplied) and the returned ``size`` is the item's byte span.
        Raises an error (surfaced by the caller as an ``isError`` result) when the
        declaration will not parse, the size is unsupported, or the item cannot be
        created at ``ea``.
        """
        ...
