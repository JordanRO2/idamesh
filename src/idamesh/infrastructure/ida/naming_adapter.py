"""IDA adapter implementing :class:`~idamesh.domain.ports.naming.NamingGateway`.

Sets the user name on the item at an address. Reads the current name first
(``ida_name.get_name``) so the completed rename can report the prior name, then
writes through ``ida_name.set_name`` with the check flag set so an invalid
identifier or a collision *fails* rather than being silently uniquified. A failed
write raises, which the application surfaces as an ``isError`` result. All
``ida_*`` imports are performed lazily inside the method so this module loads
without IDA present.
"""

from __future__ import annotations

from idamesh.domain.values.address import Address


class IdaNamingGateway:
    """:class:`~idamesh.domain.ports.naming.NamingGateway` over the IDA SDK."""

    def set_name(self, ea: Address, name: str) -> str:
        # Lazy SDK import keeps this module importable without IDA present.
        import ida_name

        address = int(ea)
        old_name = ida_name.get_name(address) or ""

        # ``SN_CHECK`` validates the identifier and refuses a colliding name
        # instead of forcing a uniquified variant; ``SN_NOWARN`` suppresses the
        # interactive warning dialog on the GUI backend.
        flags = getattr(ida_name, "SN_CHECK", 0) | getattr(ida_name, "SN_NOWARN", 0)
        if not ida_name.set_name(address, name, flags):
            raise ValueError(
                f"cannot rename {ea.hex()} to {name!r}: invalid identifier or "
                "name already in use"
            )
        return old_name
