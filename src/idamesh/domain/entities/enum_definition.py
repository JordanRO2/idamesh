"""Enum-definition entity: :class:`EnumDefinition`.

Backs the ``enum_upsert`` tool. An :class:`EnumDefinition` records one completed
create-or-extend of an enumeration type — the enum ``name`` and its
``member_count`` after the reconciliation. The *shape* (the field set a client
parses) is the interoperability contract; holding the outcome in an immutable
record is ours. A refused upsert never produces one — it surfaces as an error at
the boundary instead.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EnumDefinition:
    """A completed enum upsert: the enum name and its member count afterward."""

    name: str
    member_count: int
