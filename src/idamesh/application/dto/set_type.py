"""Command/Result DTOs for the ``set_type`` tool.

``SetTypeCommand`` carries a polymorphic address selector and the C type
declaration to apply; ``SetTypeResult`` wraps the resulting
:class:`~idamesh.domain.entities.type_application.TypeApplication`. The selector is
resolved in the use-case, which then routes the parse-and-apply through the
type-mutation gateway.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.type_application import TypeApplication


@dataclass(frozen=True)
class SetTypeCommand:
    """Input for ``set_type``.

    ``address`` is a polymorphic selector resolved to the item to retype; ``type``
    is a C declaration or function prototype (e.g. ``int f(char *)`` or
    ``unsigned int``) to parse and apply at it.
    """

    address: str
    type: str


@dataclass(frozen=True)
class SetTypeResult:
    """Output for ``set_type`` — the completed type application."""

    application: TypeApplication
