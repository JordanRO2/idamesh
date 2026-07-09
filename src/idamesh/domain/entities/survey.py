"""Survey entities — the aggregated triage snapshot of a whole database.

A :class:`BinarySurvey` is the one-call overview ``survey_binary`` returns: the
database :class:`~idamesh.domain.entities.metadata.DatabaseMetadata`, coarse
:class:`SurveyCounts`, the entry points, a :class:`RoleTally` histogram over our
authored function-role taxonomy, a :class:`NotableImport` shortlist, a
:class:`StringCategoryTally` summary, and a ranked :class:`NotableFunction` list.
The decomposition, the role taxonomy, and the notable/category shaping are all
our design; the flat field shape is what a client parses. The classification
policy that fills these lives in :mod:`idamesh.domain.services.survey`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple

from idamesh.domain.entities.metadata import DatabaseMetadata
from idamesh.domain.values.address import Address


@dataclass(frozen=True)
class SurveyCounts:
    """Coarse population counts for the whole database."""

    functions: int
    imports: int
    strings: int
    segments: int


@dataclass(frozen=True)
class RoleTally:
    """How many functions fell into one authored role bucket."""

    role: str
    count: int


@dataclass(frozen=True)
class NotableImport:
    """One imported symbol flagged interesting, with its authored category."""

    name: str
    module: str
    address: Address
    category: str


@dataclass(frozen=True)
class StringCategoryTally:
    """How many extracted strings fell into one authored string category."""

    category: str
    count: int


@dataclass(frozen=True)
class NotableFunction:
    """A ranked function in the survey shortlist with its role and degree."""

    address: Address
    name: str
    size: int
    role: str
    caller_count: int
    callee_count: int


@dataclass(frozen=True)
class BinarySurvey:
    """The aggregated triage overview of one database."""

    metadata: DatabaseMetadata
    counts: SurveyCounts
    detail_level: str
    scanned_functions: int
    truncated: bool
    entrypoints: Tuple[Address, ...] = ()
    roles: Tuple[RoleTally, ...] = ()
    notable_imports: Tuple[NotableImport, ...] = ()
    string_categories: Tuple[StringCategoryTally, ...] = ()
    top_functions: Tuple[NotableFunction, ...] = field(default=())
