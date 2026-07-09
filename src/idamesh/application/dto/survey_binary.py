"""Command/Result DTOs for ``survey_binary``.

The command carries the ``detail_level`` knob (``standard`` runs the per-function
cross-reference scan; ``minimal`` skips it for huge databases); the result wraps
the aggregated :class:`~idamesh.domain.entities.survey.BinarySurvey`.
"""

from __future__ import annotations

from dataclasses import dataclass

from idamesh.domain.entities.survey import BinarySurvey


@dataclass(frozen=True)
class SurveyBinaryCommand:
    """Input for ``survey_binary``.

    ``detail_level`` is ``"standard"`` (full role taxonomy with a bounded
    per-function xref scan and a caller-ranked shortlist) or ``"minimal"`` (a
    cheaper flags-and-size classification, size-ranked shortlist). Any other
    value is treated as ``"standard"``.
    """

    detail_level: str = "standard"


@dataclass(frozen=True)
class SurveyBinaryResult:
    """Output for ``survey_binary`` — the aggregated triage overview."""

    survey: BinarySurvey
