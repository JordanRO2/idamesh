"""Catalog registration and wire-shape projection for ``enum_upsert`` (mutating).

The ``EnumUpsertView`` ``TypedDict`` gives the schema compiler an object-rooted
``outputSchema``; :func:`enum_upsert_view` renders the completed upsert into that
flat shape (``ok`` always true on success). The tool is marked
``@registry.mutating`` so its advertised ``readOnlyHint`` is ``false``. The field
names mirror the interoperability contract; the projection is ours.
"""

from __future__ import annotations

from typing import Mapping, TypedDict

from idamesh.application.contexts.enum_upsert import EnumUpsertUseCase
from idamesh.application.dto.enum_upsert import EnumUpsertCommand
from idamesh.domain.entities.enum_definition import EnumDefinition
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation
from idamesh.interface.mcp.registry import Registry


class EnumUpsertView(TypedDict):
    """The outcome of one ``enum_upsert`` call."""

    name: str
    ok: bool
    member_count: int


def enum_upsert_view(definition: EnumDefinition) -> EnumUpsertView:
    """Project an :class:`EnumDefinition` into its wire shape."""
    return EnumUpsertView(
        name=definition.name,
        ok=True,
        member_count=definition.member_count,
    )


def register_enum_upsert(
    registry: Registry,
    *,
    enum_upsert_use_case: EnumUpsertUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``enum_upsert`` against the enum-upsert use-case (a mutating tool)."""

    @registry.tool(name="enum_upsert")
    @registry.mutating
    def enum_upsert(name: str, members: Mapping[str, int]) -> EnumUpsertView:
        """Create or update an enumeration type without destroying its existing
        members. ``name`` is the enum type name; ``members`` is an object mapping
        each member name to its integer value. The enum is created when missing;
        each supplied member is added when absent or updated when its value changed,
        while members already present and not listed are preserved. The result
        reports the enum ``name``, ``ok``, and its ``member_count`` afterward. This
        modifies the database. An invalid name, an empty or malformed member map, or
        a member the database refuses yields an error result rather than failing the
        protocol request."""
        command = EnumUpsertCommand(name=name, members=members)
        result = run_mutation(
            executor, lambda: enum_upsert_use_case.execute(command)
        )
        return enum_upsert_view(result.definition)
