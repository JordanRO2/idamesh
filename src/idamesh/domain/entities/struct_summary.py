"""The :class:`StructSummary` entity — one row of a ``search_structs`` result.

A struct summary is the compact identity of an aggregate (struct or union) type:
its ``name``, its total byte ``size``, and how many members it declares
(``member_count``). It backs ``search_structs``, which lists aggregate types
matching a name substring without paying to materialize each type's full member
layout. The *shape* (name + size + member count per row) is the interoperability
contract a client parses; keeping a distinct lightweight entity, rather than
returning the fuller :class:`~idamesh.domain.entities.struct_layout.StructLayout`,
is our choice so the search endpoint stays cheap.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StructSummary:
    """A single aggregate type summarized for a search hit."""

    name: str
    size: int
    member_count: int
