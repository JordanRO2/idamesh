"""IDA adapter implementing :class:`~idamesh.domain.ports.code_definition.CodeDefinitionGateway`.

Backs the ``define_func`` and ``undefine`` tools. :meth:`define_func` creates a
function with ``ida_funcs.add_func`` (letting the analyzer infer the extent) and
reads back the resulting name (``ida_name.get_name``); :meth:`undefine` reverts the
item at an address with ``ida_funcs.del_func`` (when a function *starts* there) or
``ida_bytes.del_items`` (any other code/data). A create the analyzer refuses or an
address with nothing to undefine raises — surfaced by the application as an
``isError`` result. All ``ida_*`` imports are performed lazily inside the methods so
this module loads without IDA present.
"""

from __future__ import annotations

from typing import Optional

from idamesh.domain.values.address import Address


class IdaCodeDefinitionGateway:
    """:class:`~idamesh.domain.ports.code_definition.CodeDefinitionGateway` over the SDK."""

    def define_func(self, ea: Address) -> Optional[str]:
        """Create a function at ``ea`` and return its name (``None`` if unnamed).

        ``ida_funcs.add_func`` promotes the code at the address into a function,
        letting the analyzer infer the end. A falsey return means the analyzer
        refused (no decodable instruction, or a function already spans the
        address); that raises, which the application surfaces as an ``isError``
        result. On success the new function's current name is read back through
        ``ida_name.get_name`` and reported (``None`` when it carries no name).
        """
        # Lazy SDK imports keep this module importable without IDA present.
        import ida_funcs
        import ida_name

        address = int(ea)
        if not ida_funcs.add_func(address):
            raise ValueError(
                f"cannot create a function at {ea.hex()}: no decodable "
                "instruction to base one on, or one already exists there"
            )
        return ida_name.get_name(address) or None

    def undefine(self, ea: Address) -> None:
        """Undefine the item at ``ea``, reverting it to raw bytes.

        When a function *starts* at ``ea`` the whole function is removed with
        ``ida_funcs.del_func``; otherwise the code or data item covering the
        address is reverted with ``ida_bytes.del_items``. A falsey return from
        either call means nothing at ``ea`` could be undefined and raises, which
        the application surfaces as an ``isError`` result.
        """
        # Lazy SDK imports keep this module importable without IDA present.
        import ida_bytes
        import ida_funcs

        address = int(ea)
        func = ida_funcs.get_func(address)
        if func is not None and func.start_ea == address:
            if not ida_funcs.del_func(address):
                raise ValueError(f"failed to undefine the function at {ea.hex()}")
            return
        if not ida_bytes.del_items(address):
            raise ValueError(f"failed to undefine the item at {ea.hex()}")
