"""Command/Result DTOs for the ``add_bookmark`` tool.

``AddBookmarkCommand`` carries a polymorphic address selector and the bookmark
``description``; ``AddBookmarkResult`` wraps the resulting
:class:`~idamesh.domain.entities.bookmark.Bookmark`. The selector is resolved in
the use-case, which then routes the mark through the bookmark gateway.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.bookmark import Bookmark


@dataclass(frozen=True)
class AddBookmarkCommand:
    """Input for ``add_bookmark``.

    ``address`` is a polymorphic selector resolved to the address to mark;
    ``description`` is the label shown for the bookmark.
    """

    address: str
    description: str


@dataclass(frozen=True)
class AddBookmarkResult:
    """Output for ``add_bookmark`` — the completed bookmark."""

    bookmark: Bookmark
