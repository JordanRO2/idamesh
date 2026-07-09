"""Catalog registration and wire-shape projection for ``survey_binary``.

The nested ``*View`` ``TypedDict``s give the schema compiler an object-rooted
``outputSchema``; :func:`survey_binary_view` renders the aggregated
:class:`~idamesh.domain.entities.survey.BinarySurvey` into that flat shape
(addresses as ``0x`` hex). The metadata block reuses the shared
:func:`~idamesh.interface.catalog.views.metadata_view`. The field names and the
projection are ours.
"""

from __future__ import annotations

from typing import List, Literal, TypedDict

from idamesh.application.contexts.survey_binary import SurveyBinaryUseCase
from idamesh.application.dto.survey_binary import (
    SurveyBinaryCommand,
    SurveyBinaryResult,
)
from idamesh.domain.entities.survey import (
    BinarySurvey,
    NotableFunction,
    NotableImport,
    RoleTally,
    StringCategoryTally,
)
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_use_case
from idamesh.interface.catalog.views import MetadataView, metadata_view
from idamesh.interface.mcp.registry import Registry


class SurveyCountsView(TypedDict):
    """Coarse population counts for the surveyed database."""

    functions: int
    imports: int
    strings: int
    segments: int


class RoleTallyView(TypedDict):
    """One function-role bucket and its population."""

    role: str
    count: int


class NotableImportView(TypedDict):
    """One flagged import with its authored category."""

    name: str
    module: str
    address: str
    category: str


class StringCategoryView(TypedDict):
    """One string category and its population."""

    category: str
    count: int


class NotableFunctionView(TypedDict):
    """One ranked function in the survey shortlist."""

    address: str
    name: str
    size: int
    role: str
    caller_count: int
    callee_count: int


class SurveyBinaryView(TypedDict):
    """The aggregated triage overview of one database."""

    metadata: MetadataView
    counts: SurveyCountsView
    detail_level: str
    scanned_functions: int
    truncated: bool
    entrypoints: List[str]
    roles: List[RoleTallyView]
    notable_imports: List[NotableImportView]
    string_categories: List[StringCategoryView]
    top_functions: List[NotableFunctionView]


def _role_tally_view(tally: RoleTally) -> RoleTallyView:
    return RoleTallyView(role=tally.role, count=tally.count)


def _notable_import_view(item: NotableImport) -> NotableImportView:
    return NotableImportView(
        name=item.name,
        module=item.module,
        address=item.address.hex(),
        category=item.category,
    )


def _string_category_view(tally: StringCategoryTally) -> StringCategoryView:
    return StringCategoryView(category=tally.category, count=tally.count)


def _notable_function_view(item: NotableFunction) -> NotableFunctionView:
    return NotableFunctionView(
        address=item.address.hex(),
        name=item.name,
        size=item.size,
        role=item.role,
        caller_count=item.caller_count,
        callee_count=item.callee_count,
    )


def survey_binary_view(result: SurveyBinaryResult) -> SurveyBinaryView:
    """Project a ``survey_binary`` result into its wire shape."""
    survey: BinarySurvey = result.survey
    return SurveyBinaryView(
        metadata=metadata_view(survey.metadata),
        counts=SurveyCountsView(
            functions=survey.counts.functions,
            imports=survey.counts.imports,
            strings=survey.counts.strings,
            segments=survey.counts.segments,
        ),
        detail_level=survey.detail_level,
        scanned_functions=survey.scanned_functions,
        truncated=survey.truncated,
        entrypoints=[ea.hex() for ea in survey.entrypoints],
        roles=[_role_tally_view(tally) for tally in survey.roles],
        notable_imports=[
            _notable_import_view(item) for item in survey.notable_imports
        ],
        string_categories=[
            _string_category_view(tally) for tally in survey.string_categories
        ],
        top_functions=[
            _notable_function_view(item) for item in survey.top_functions
        ],
    )


def register_survey_binary(
    registry: Registry,
    *,
    survey_binary_use_case: SurveyBinaryUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``survey_binary`` against the triage-aggregation use-case."""

    @registry.tool(name="survey_binary")
    def survey_binary(
        detail_level: Literal["standard", "minimal"] = "standard"
    ) -> SurveyBinaryView:
        """Return a one-call triage overview of the whole database, so an agent
        need not fan out to ``list_funcs`` / ``imports`` / ``list_strings``
        separately to orient. The overview bundles the database ``metadata``,
        coarse ``counts`` (functions, imports, strings, segments), the
        ``entrypoints``, a ``roles`` histogram over an authored function-role
        taxonomy (``thunk`` / ``library`` / ``small-leaf`` / ``leaf`` / ``hub`` /
        ``dispatcher`` / ``large`` / ``ordinary``), a ``notable_imports``
        shortlist tagged by category (``network`` / ``process`` / ``filesystem``
        / ``registry`` / ``crypto`` / ``memory`` / ``loader`` / ``anti-debug``), a
        ``string_categories`` summary, and a ``top_functions`` shortlist ranked by
        caller count. ``detail_level`` is ``"standard"`` (full classification with
        a bounded per-function cross-reference scan) or ``"minimal"`` (a cheaper
        flags-and-size pass for very large databases). Read-only."""
        command = SurveyBinaryCommand(detail_level=detail_level)
        result = run_use_case(
            executor, lambda: survey_binary_use_case.execute(command)
        )
        return survey_binary_view(result)
