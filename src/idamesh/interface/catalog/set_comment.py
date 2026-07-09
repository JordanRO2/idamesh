"""Catalog registration and wire-shape projection for ``set_comment`` (mutating).

The ``SetCommentView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`set_comment_view` renders the completed write into that
flat shape (address as ``0x`` hex, ``ok`` always true on success). The tool is
marked ``@registry.mutating`` so its advertised ``readOnlyHint`` is ``false``. The
field names mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import TypedDict

from idamesh.application.contexts.set_comment import SetCommentUseCase
from idamesh.application.dto.set_comment import SetCommentCommand
from idamesh.domain.entities.comment import CommentEdit
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class SetCommentView(TypedDict):
    """The outcome of one ``set_comment`` call."""

    address: str
    comment: str
    ok: bool


def set_comment_view(edit: CommentEdit) -> SetCommentView:
    """Project a :class:`CommentEdit` into its wire shape."""
    return SetCommentView(
        address=edit.address.hex(),
        comment=edit.comment,
        ok=True,
    )


def register_set_comment(
    registry: Registry,
    *,
    set_comment_use_case: SetCommentUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``set_comment`` against the set-comment use-case (mutating)."""

    @registry.tool(name="set_comment")
    @registry.mutating
    def set_comment(
        address: str,
        comment: str,
        repeatable: bool = False,
        function: bool = False,
    ) -> SetCommentView:
        """Attach ``comment`` at ``address``. The ``address`` may be a hexadecimal
        literal (``0x…``), a decimal literal, or a symbol name; it is resolved
        first. By default the text is written as the item comment at that address;
        set ``function`` to route it to the enclosing function's comment instead,
        and set ``repeatable`` to use the repeatable slot (echoed at every
        cross-reference) rather than the anchored one. An empty ``comment`` clears
        the chosen slot. The result reports the resolved ``address`` (``0x`` hex),
        the ``comment`` written, and ``ok``. This modifies the database. A function
        comment requested where no function owns the address, or an unresolvable
        address, yields an error result rather than failing the protocol
        request."""
        command = SetCommentCommand(
            address=address,
            comment=comment,
            repeatable=repeatable,
            function=function,
        )
        result = run_mutation(
            executor, lambda: set_comment_use_case.execute(command)
        )
        return set_comment_view(result.edit)
