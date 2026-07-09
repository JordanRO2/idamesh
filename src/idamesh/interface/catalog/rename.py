"""Catalog registration and wire-shape projection for ``rename`` (mutating).

The ``RenameView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`rename_view` renders the completed rename into that flat
shape (address as ``0x`` hex, ``ok`` always true on success). The tool is marked
``@registry.mutating`` so its advertised ``readOnlyHint`` is ``false``. The field
names mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.rename import RenameUseCase
from idamesh.application.dto.rename import RenameCommand
from idamesh.domain.entities.rename import Renaming
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class RenameView(TypedDict):
    """The outcome of one ``rename`` call."""

    address: str
    old_name: str
    name: str
    ok: bool


def rename_view(renaming: Renaming) -> RenameView:
    """Project a :class:`Renaming` into its wire shape."""
    return RenameView(
        address=renaming.address.hex(),
        old_name=renaming.old_name,
        name=renaming.name,
        ok=True,
    )


def register_rename(
    registry: Registry,
    *,
    rename_use_case: RenameUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``rename`` against the rename use-case (a mutating tool)."""

    @registry.tool(name="rename")
    @registry.mutating
    def rename(address: str, name: str) -> RenameView:
        """Set the user name of the item at ``address`` to ``name``. The
        ``address`` may be a hexadecimal literal (``0x…``), a decimal literal, or a
        symbol name; it is resolved first, and may point at a function or a data
        item. The result reports the resolved ``address`` (``0x`` hex), the
        ``old_name`` that was in force beforehand, the new ``name``, and ``ok``.
        This modifies the database. An empty or invalid identifier, a name that
        clashes with an existing symbol, or an unresolvable address yields an error
        result rather than failing the protocol request."""
        command = RenameCommand(address=address, name=name)
        result = run_mutation(
            executor, lambda: rename_use_case.execute(command)
        )
        return rename_view(result.renaming)
