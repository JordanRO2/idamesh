"""The comment gateway port: attach a comment at an address.

One port serves the ``set_comment`` tool. :meth:`set_comment` writes a comment at
an effective address, selecting between two orthogonal placements: the ``function``
flag routes the text to the enclosing function's comment rather than the item at
``ea``, and ``repeatable`` chooses the repeatable comment slot (echoed at every
cross-reference) over the ordinary anchored slot. Writing an empty string clears
the selected slot. Requesting a function comment at an address that lies in no
function raises, surfaced by the caller as an ``isError`` result.
"""

from __future__ import annotations

from typing import Protocol

from idamesh.domain.values.address import Address


class CommentGateway(Protocol):
    """Write-side access to the comment slots at an address."""

    def set_comment(
        self,
        ea: Address,
        comment: str,
        *,
        repeatable: bool,
        function: bool,
    ) -> None:
        """Write ``comment`` at ``ea`` into the selected comment slot.

        ``function`` selects the enclosing function's comment (rather than the
        item comment at ``ea``); ``repeatable`` selects the repeatable slot (rather
        than the anchored one). An empty ``comment`` clears the chosen slot. Raises
        an error (surfaced by the caller as an ``isError`` result) when a function
        comment is requested at an address that belongs to no function, or when the
        write is otherwise refused by the database.
        """
        ...
