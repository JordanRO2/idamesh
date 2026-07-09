"""The naming gateway port: set the user-visible name at an address.

This is the *write* counterpart to the read-side symbol resolution on
:class:`~idamesh.domain.ports.database.DatabaseGateway`. One port serves the
``rename`` tool. :meth:`set_name` installs a user name on the item (function or
data) at an effective address and returns the name that was in force beforehand,
so the caller can report the ``old_name`` → ``name`` transition. A name the SDK
rejects — an invalid identifier or one that clashes with an existing symbol —
raises, which the application surfaces as an ``isError`` result rather than a
silently-mangled rename. Validity enforcement is the adapter's concern; the port
only fixes the contract.
"""

from __future__ import annotations

from typing import Protocol

from idamesh.domain.values.address import Address


class NamingGateway(Protocol):
    """Write-side access to the item name at an address."""

    def set_name(self, ea: Address, name: str) -> str:
        """Set the user name at ``ea`` to ``name`` and return the prior name.

        The returned string is the name that was displayed at ``ea`` *before* the
        change (empty when the item was unnamed). Raises an error (surfaced by the
        caller as an ``isError`` result) when ``name`` is not a legal identifier or
        collides with a name already bound elsewhere — the rename is refused, not
        forced to a uniquified variant.
        """
        ...
