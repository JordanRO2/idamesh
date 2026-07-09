"""The ``add_bookmark`` use-case: mark a resolved address with a description.

Resolves the polymorphic selector against the database gateway (mirroring the read
tools), validates that a non-empty description was supplied, then routes the mark
through the :class:`~idamesh.domain.ports.bookmark.BookmarkGateway`, which returns
the slot the mark occupies. The empty-description guard and the result assembly are
the application's; the SDK-level bookmark write is the gateway's.
"""

from __future__ import annotations

from idamesh.application.dto.add_bookmark import (
    AddBookmarkCommand,
    AddBookmarkResult,
)
from idamesh.domain.entities.bookmark import Bookmark
from idamesh.domain.ports.bookmark import BookmarkGateway
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.values.address import Selector


def _require_description(description: str) -> str:
    """Return ``description`` if it is a non-empty, non-blank string, else raise."""
    if not isinstance(description, str):
        raise ValueError(
            f"description must be a string, got {type(description).__name__}"
        )
    stripped = description.strip()
    if not stripped:
        raise ValueError("description must not be empty")
    return stripped


class AddBookmarkUseCase:
    """Resolve a selector and add a marked position at the address there."""

    def __init__(
        self, bookmarks: BookmarkGateway, database: DatabaseGateway
    ) -> None:
        self._bookmarks = bookmarks
        self._database = database

    def execute(self, command: AddBookmarkCommand) -> AddBookmarkResult:
        """Resolve ``command.address`` and mark it with ``command.description``.

        The description is checked non-empty, the selector is resolved against the
        database gateway, then the bookmark gateway records the mark and reports its
        slot. The completed bookmark is wrapped as a
        :class:`~idamesh.domain.entities.bookmark.Bookmark`. An empty description,
        an address that cannot be bookmarked, or an unresolvable address surfaces as
        an error the interface layer renders as an ``isError`` result.
        """
        description = _require_description(command.description)
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        slot = self._bookmarks.add(ea, description)
        bookmark = Bookmark(address=ea, slot=slot)
        return AddBookmarkResult(bookmark=bookmark)
