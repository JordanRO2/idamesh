"""The code-definition gateway port: create or undefine an item at an address.

Shared write surface for the ``define_func`` and ``undefine`` tools.
:meth:`define_func` promotes the code at an effective address into a function,
letting the analyzer infer the extent, and returns the resulting function's name
(``None`` when it ends up unnamed) so ``define_func`` can report it.
:meth:`undefine` reverts the item (function, code, or data) at an address back to
raw undefined bytes. A definition the database refuses — no instruction to base a
function on, or an address that cannot be undefined — raises a domain error the
caller surfaces as an ``isError`` result. The SDK-level create/delete is the
adapter's job; this port only fixes the contract.
"""

from __future__ import annotations

from typing import Optional, Protocol

from idamesh.domain.values.address import Address


class CodeDefinitionGateway(Protocol):
    """Write-side creation and removal of a function/item at an address."""

    def define_func(self, ea: Address) -> Optional[str]:
        """Create a function at ``ea`` and return its name (``None`` if unnamed).

        The analyzer infers the function's end. On success the new function's
        current name is returned, or ``None`` when it carries no user/auto name.
        Raises an error (surfaced by the caller as an ``isError`` result) when a
        function cannot be created at ``ea`` (e.g. no decodable instruction there).
        """
        ...

    def undefine(self, ea: Address) -> None:
        """Undefine the item at ``ea``, reverting it to raw bytes.

        Removes the function, code, or data definition covering ``ea``. Raises an
        error (surfaced by the caller as an ``isError`` result) when nothing at
        ``ea`` can be undefined.
        """
        ...
