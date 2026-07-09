"""The decompiler gateway port: EA -> pseudocode."""

from __future__ import annotations

from typing import Protocol

from idamesh.domain.entities.decompilation import Pseudocode
from idamesh.domain.values.address import Address


class DecompilerGateway(Protocol):
    """Hex-Rays-style decompilation of a single function."""

    def is_available(self) -> bool:
        """``True`` when a decompiler is licensed and loadable for this database."""
        ...

    def decompile(self, ea: Address) -> Pseudocode:
        """Decompile the function at (or containing) ``ea`` to pseudocode.

        Raises ``ValueError`` when ``ea`` is not within a function, and a
        decompiler-specific error when the decompiler is unavailable or fails.
        """
        ...
