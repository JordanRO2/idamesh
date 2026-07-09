"""Command/Result DTOs for the ``set_comment`` tool.

``SetCommentCommand`` carries a polymorphic address selector, the comment text,
and the two slot selectors (``repeatable`` / ``function``); ``SetCommentResult``
wraps the resulting :class:`~idamesh.domain.entities.comment.CommentEdit`. The
selector is resolved in the use-case, which then routes the write through the
comment gateway.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.comment import CommentEdit


@dataclass(frozen=True)
class SetCommentCommand:
    """Input for ``set_comment``.

    ``address`` is a polymorphic selector resolved to the commented item;
    ``comment`` is the text to write (empty clears the slot). ``repeatable``
    selects the repeatable comment slot over the anchored one, and ``function``
    routes the text to the enclosing function's comment instead of the item at the
    address.
    """

    address: str
    comment: str
    repeatable: bool = False
    function: bool = False


@dataclass(frozen=True)
class SetCommentResult:
    """Output for ``set_comment`` — the completed comment write."""

    edit: CommentEdit
