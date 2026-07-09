"""The :class:`Pseudocode` entity — output of the decompiler port.

Carries both the joined pseudocode ``text`` (the primary human-readable payload)
and the split ``lines`` so a client can address individual rows without
re-splitting.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class Pseudocode:
    """Decompiled pseudocode for one function."""

    ea: Address
    text: str
    lines: tuple[str, ...] = ()
    name: str | None = None
