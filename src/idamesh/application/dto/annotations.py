"""Command/Result DTOs for ``export_annotations`` / ``apply_annotations``.

``ExportAnnotationsCommand`` carries the optional function-selector filter and the
type-inclusion toggle; its selectors are resolved to effective addresses in the
use-case (mirroring the read tools) before the gateway is asked to read.
``ApplyAnnotationsCommand`` carries an already-parsed domain
:class:`~idamesh.domain.services.reconciliation.AnnotationRecord` — the interface
layer parses the wire document via
:mod:`idamesh.application.annotation_wire` before constructing the command, so the
application never touches JSON. The results wrap the produced record / apply report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple

from idamesh.domain.entities.annotations import AnnotationApplyReport
from idamesh.domain.services.reconciliation import AnnotationRecord


@dataclass(frozen=True)
class ExportAnnotationsCommand:
    """Input for ``export_annotations``.

    ``funcs`` is an optional tuple of polymorphic selectors (hex/decimal/symbol)
    restricting the export to those functions; ``None`` exports the whole database.
    ``include_types`` toggles the prototype/type read.
    """

    funcs: Optional[Tuple[str, ...]] = None
    include_types: bool = True


@dataclass(frozen=True)
class ExportAnnotationsResult:
    """Output for ``export_annotations`` — the exported record."""

    record: AnnotationRecord


@dataclass(frozen=True)
class ApplyAnnotationsCommand:
    """Input for ``apply_annotations`` — the domain record to write into this copy."""

    record: AnnotationRecord


@dataclass(frozen=True)
class ApplyAnnotationsResult:
    """Output for ``apply_annotations`` — the best-effort apply tally."""

    report: AnnotationApplyReport = field(default_factory=AnnotationApplyReport)
