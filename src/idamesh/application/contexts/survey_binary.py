"""The ``survey_binary`` use-case — a one-call triage overview.

Aggregates a triage snapshot by fanning out over the existing read ports —
database metadata and counts, a bounded page of functions, imports, and strings —
and delegating every qualitative judgement (function role, import category, string
category) to the pure :class:`~idamesh.domain.services.survey.SurveyService`. In
``standard`` detail the scanned functions are classified with a per-function
cross-reference degree and ranked by caller count; in ``minimal`` detail the xref
scan is skipped and functions are classified and ranked by size alone. The
composition and the caps are ours.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

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
    SurveyCounts,
)
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.ports.functions import FunctionRepository
from idamesh.domain.ports.imports import ImportRepository
from idamesh.domain.ports.strings import StringsRepository
from idamesh.domain.ports.xrefs import XrefRepository
from idamesh.domain.services.survey import SurveyService
from idamesh.domain.values.pagination import PageRequest

#: Detail levels the survey honors; anything else falls back to ``standard``.
DETAIL_STANDARD = "standard"
DETAIL_MINIMAL = "minimal"

#: How many functions the survey pulls in and classifies in one pass.
SURVEY_FUNCTION_SCAN: int = 1000
#: How many imports are scanned for the notable shortlist.
SURVEY_IMPORT_SCAN: int = 1000
#: How many strings are scanned for the category summary.
SURVEY_STRING_SCAN: int = 1000
#: How many functions the ranked shortlist keeps.
SURVEY_TOP_FUNCTIONS: int = 25
#: How many entries the notable-import shortlist keeps.
SURVEY_NOTABLE_IMPORTS: int = 40


class SurveyBinaryUseCase:
    """Aggregate a triage overview over the read ports + the survey taxonomy."""

    def __init__(
        self,
        database: DatabaseGateway,
        functions: FunctionRepository,
        imports: ImportRepository,
        strings: StringsRepository,
        xrefs: XrefRepository,
        survey: SurveyService,
    ) -> None:
        self._database = database
        self._functions = functions
        self._imports = imports
        self._strings = strings
        self._xrefs = xrefs
        self._survey = survey

    def execute(self, command: SurveyBinaryCommand) -> SurveyBinaryResult:
        """Assemble the :class:`BinarySurvey` for the open database."""
        detail = (
            DETAIL_MINIMAL
            if command.detail_level == DETAIL_MINIMAL
            else DETAIL_STANDARD
        )

        metadata = self._database.metadata()
        function_total = self._count(self._functions)
        import_total = self._count(self._imports)
        string_total = self._count(self._strings)

        func_page = self._functions.list(
            PageRequest.of(0, SURVEY_FUNCTION_SCAN).clamp()
        )
        functions = list(func_page.items)

        roles, top_functions = self._classify_functions(functions, detail)
        notable_imports = self._collect_notable_imports()
        string_categories = self._summarize_strings()

        entrypoints: Tuple = tuple(
            ea for ea in (metadata.entrypoint,) if ea is not None
        )
        counts = SurveyCounts(
            functions=function_total,
            imports=import_total,
            strings=string_total,
            segments=metadata.segment_count,
        )
        survey = BinarySurvey(
            metadata=metadata,
            counts=counts,
            detail_level=detail,
            scanned_functions=len(functions),
            truncated=function_total > len(functions),
            entrypoints=entrypoints,
            roles=roles,
            notable_imports=notable_imports,
            string_categories=string_categories,
            top_functions=top_functions,
        )
        return SurveyBinaryResult(survey=survey)

    # -- internals --------------------------------------------------------- #

    def _classify_functions(
        self, functions: List, detail: str
    ) -> Tuple[Tuple[RoleTally, ...], Tuple[NotableFunction, ...]]:
        role_counts: Dict[str, int] = {}
        scored: List[Tuple[int, NotableFunction]] = []
        for func in functions:
            if detail == DETAIL_STANDARD:
                caller_count = len(self._safe_refs_to(func.ea))
                callee_count = len(self._safe_callees(func.ea))
                role = self._survey.classify_function(
                    func, caller_count=caller_count, callee_count=callee_count
                )
                rank = caller_count
            else:
                caller_count = 0
                callee_count = 0
                role = self._survey.classify_cheap(func)
                rank = func.size
            role_counts[role] = role_counts.get(role, 0) + 1
            scored.append(
                (
                    rank,
                    NotableFunction(
                        address=func.ea,
                        name=func.name,
                        size=func.size,
                        role=role,
                        caller_count=caller_count,
                        callee_count=callee_count,
                    ),
                )
            )

        scored.sort(key=lambda item: (item[0], item[1].size), reverse=True)
        top = tuple(entry for _, entry in scored[:SURVEY_TOP_FUNCTIONS])
        roles = tuple(
            sorted(
                (RoleTally(role=role, count=count) for role, count in role_counts.items()),
                key=lambda tally: (tally.count, tally.role),
                reverse=True,
            )
        )
        return roles, top

    def _collect_notable_imports(self) -> Tuple[NotableImport, ...]:
        page = self._imports.list(PageRequest.of(0, SURVEY_IMPORT_SCAN).clamp())
        notable: List[NotableImport] = []
        for imp in page.items:
            category = self._survey.categorize_import(imp.name, imp.module)
            if category is None:
                continue
            notable.append(
                NotableImport(
                    name=imp.name,
                    module=imp.module,
                    address=imp.ea,
                    category=category,
                )
            )
            if len(notable) >= SURVEY_NOTABLE_IMPORTS:
                break
        return tuple(notable)

    def _summarize_strings(self) -> Tuple[StringCategoryTally, ...]:
        page = self._strings.list(PageRequest.of(0, SURVEY_STRING_SCAN).clamp())
        counts: Dict[str, int] = {}
        for item in page.items:
            category = self._survey.categorize_string(item.value)
            counts[category] = counts.get(category, 0) + 1
        return tuple(
            sorted(
                (
                    StringCategoryTally(category=category, count=count)
                    for category, count in counts.items()
                ),
                key=lambda tally: (tally.count, tally.category),
                reverse=True,
            )
        )

    def _safe_refs_to(self, ea):
        try:
            return self._xrefs.refs_to(ea)
        except (LookupError, RuntimeError):
            return []

    def _safe_callees(self, ea):
        try:
            return self._xrefs.callees(ea)
        except (LookupError, RuntimeError):
            return []

    @staticmethod
    def _count(repo) -> int:
        try:
            return int(repo.count())
        except (LookupError, RuntimeError, ValueError):
            return 0
