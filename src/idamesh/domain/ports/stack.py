"""The stack gateway port: define and remove stack-frame variables.

Shared write surface for the ``declare_stack`` and ``delete_stack`` tools.
:meth:`declare` defines a typed variable on the frame of the function whose entry
is at an effective address — placing it at a frame offset and giving it a name and
C type — while :meth:`delete` removes a named frame variable. A declaration the
frame refuses (bad type, colliding member, offset outside the frame), or a delete
of a name the frame does not carry, raises a domain error the caller surfaces as an
``isError`` result. The SDK-level frame edit is the adapter's job; this port only
fixes the contract.
"""

from __future__ import annotations

from typing import Protocol

from idamesh.domain.values.address import Address


class StackGateway(Protocol):
    """Write-side definition and removal of stack-frame variables."""

    def declare(self, func: Address, name: str, type: str, offset: int) -> None:
        """Define frame variable ``name`` of C type ``type`` at ``offset``.

        ``func`` is the entry address of the owning function; ``offset`` is the
        signed frame offset the variable occupies. Raises an error (surfaced by the
        caller as an ``isError`` result) when ``func`` names no function, the type
        will not parse, or the variable cannot be placed at ``offset``.
        """
        ...

    def delete(self, func: Address, name: str) -> None:
        """Remove frame variable ``name`` from the function at ``func``.

        Raises an error (surfaced by the caller as an ``isError`` result) when
        ``func`` names no function or the frame carries no variable ``name``.
        """
        ...
