"""Catalog registration and wire-shape projection for ``add_bookmark`` (mutating).

The ``AddBookmarkView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`add_bookmark_view` renders the completed mark into that
flat shape (address as ``0x`` hex, ``ok`` always true on success). The tool is
marked ``@registry.mutating`` so its advertised ``readOnlyHint`` is ``false``. The
field names mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.add_bookmark import AddBookmarkUseCase
from idamesh.application.dto.add_bookmark import AddBookmarkCommand
from idamesh.domain.entities.bookmark import Bookmark
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class AddBookmarkView(TypedDict):
    """The outcome of one ``add_bookmark`` call."""

    address: str
    slot: int
    ok: bool


def add_bookmark_view(bookmark: Bookmark) -> AddBookmarkView:
    """Project a :class:`Bookmark` into its wire shape."""
    return AddBookmarkView(
        address=bookmark.address.hex(),
        slot=bookmark.slot,
        ok=True,
    )


def register_add_bookmark(
    registry: Registry,
    *,
    add_bookmark_use_case: AddBookmarkUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``add_bookmark`` against the add-bookmark use-case (mutating)."""

    @registry.tool(name="add_bookmark")
    @registry.mutating
    def add_bookmark(address: str, description: str) -> AddBookmarkView:
        """Add a marked position (bookmark) at ``address``. The ``address`` may be a
        hexadecimal literal (``0x…``), a decimal literal, or a symbol name; it is
        resolved first. ``description`` is the label shown for the mark. When the
        address is already bookmarked its slot is reused and the description
        updated. The result reports the resolved ``address`` (``0x`` hex), the
        ``slot`` the mark occupies, and ``ok``. This modifies the database. An
        empty description, an address that cannot be bookmarked, or an unresolvable
        address yields an error result rather than failing the protocol request."""
        command = AddBookmarkCommand(address=address, description=description)
        result = run_mutation(
            executor, lambda: add_bookmark_use_case.execute(command)
        )
        return add_bookmark_view(result.bookmark)
