"""The :class:`Function` entity — a function as returned to a client.

Field choices are ours; the *shape* (address, name, size, kind flags) is the
interoperability contract a client parses.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class Function:
    """A single function in the database."""

    ea: Address
    name: str
    size: int
    end_ea: Address | None = None
    flags: int = 0
    is_library: bool = False
    is_thunk: bool = False

    @property
    def start_ea(self) -> Address:
        """Alias for :attr:`ea`, the function's entry address."""
        return self.ea
