"""Comment entity: :class:`CommentEdit`.

Backs the ``set_comment`` tool. A :class:`CommentEdit` records one completed
comment write at a resolved address — the ``comment`` text and which slot it
landed in (``repeatable`` vs anchored, ``function`` vs item). The *shape* (the
field set a client parses) is the interoperability contract; holding the outcome
in an immutable record is ours. A refused write never produces one — it surfaces
as an error at the boundary instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class CommentEdit:
    """A completed comment write: where it went, its text, and the slot chosen."""

    address: Address
    comment: str
    repeatable: bool
    function: bool
