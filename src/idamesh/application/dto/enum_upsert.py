"""Command/Result DTOs for the ``enum_upsert`` tool.

``EnumUpsertCommand`` carries the enum ``name`` and a ``members`` map (member name
→ integer value); ``EnumUpsertResult`` wraps the resulting
:class:`~idamesh.domain.entities.enum_definition.EnumDefinition`. No address is
involved — the use-case validates the inputs and routes the create-or-extend
through the enum gateway.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from idamesh.domain.entities.enum_definition import EnumDefinition


@dataclass(frozen=True)
class EnumUpsertCommand:
    """Input for ``enum_upsert``.

    ``name`` is the enum type name; ``members`` maps each member name to its
    integer value. Members already present and not listed are preserved.
    """

    name: str
    members: Mapping[str, int]


@dataclass(frozen=True)
class EnumUpsertResult:
    """Output for ``enum_upsert`` — the completed enum upsert."""

    definition: EnumDefinition
