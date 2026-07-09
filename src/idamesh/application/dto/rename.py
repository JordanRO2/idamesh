"""Command/Result DTOs for the ``rename`` tool.

``RenameCommand`` carries a polymorphic address selector and the new ``name`` to
install; ``RenameResult`` wraps the resulting :class:`~idamesh.domain.entities.rename.Renaming`.
The selector is resolved in the use-case (mirroring the read tools), and the new
name is validated there before the naming gateway is asked to write it.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.rename import Renaming


@dataclass(frozen=True)
class RenameCommand:
    """Input for ``rename``.

    ``address`` is a polymorphic selector — a hex literal (``0x…``), a decimal
    literal, or a symbol name — resolved to the item to rename; ``name`` is the new
    user name to install on it.
    """

    address: str
    name: str


@dataclass(frozen=True)
class RenameResult:
    """Output for ``rename`` — the completed name change."""

    renaming: Renaming
