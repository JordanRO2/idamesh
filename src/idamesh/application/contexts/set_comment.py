"""The ``set_comment`` use-case: attach a comment at a resolved address.

Resolves the polymorphic selector against the database gateway (mirroring the read
tools), then routes the text through the
:class:`~idamesh.domain.ports.comments.CommentGateway`, selecting the slot from the
command's ``repeatable`` / ``function`` flags. The slot-selection policy lives here
in the application layer; the gateway performs the one obvious SDK write for the
chosen slot.
"""

from __future__ import annotations

from idamesh.application.dto.set_comment import (
    SetCommentCommand,
    SetCommentResult,
)
from idamesh.domain.entities.comment import CommentEdit
from idamesh.domain.ports.comments import CommentGateway
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.values.address import Selector


class SetCommentUseCase:
    """Resolve a selector and write a comment into a chosen slot at that address."""

    def __init__(
        self, comments: CommentGateway, database: DatabaseGateway
    ) -> None:
        self._comments = comments
        self._database = database

    def execute(self, command: SetCommentCommand) -> SetCommentResult:
        """Resolve ``command.address`` and write ``command.comment`` at it.

        The selector is parsed and resolved against the database gateway; the
        comment gateway then writes the text into the slot chosen by
        ``command.repeatable`` (repeatable vs anchored) and ``command.function``
        (function vs item). The completed write is wrapped as a
        :class:`~idamesh.domain.entities.comment.CommentEdit`. An unresolvable
        address, or a function comment requested where no function owns the
        address, surfaces as an error the interface layer renders as an ``isError``
        result.
        """
        selector = Selector.parse(command.address)
        ea = self._database.resolve(selector)
        self._comments.set_comment(
            ea,
            command.comment,
            repeatable=command.repeatable,
            function=command.function,
        )
        edit = CommentEdit(
            address=ea,
            comment=command.comment,
            repeatable=command.repeatable,
            function=command.function,
        )
        return SetCommentResult(edit=edit)
