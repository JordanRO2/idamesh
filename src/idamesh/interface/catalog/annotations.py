"""Catalog registration + wire projection for the annotation worker tools.

Two worker tools of the merge-back live here:

* ``export_annotations`` — read-only; returns this copy's user annotations as the
  frozen :class:`~idamesh.application.annotation_wire.AnnotationRecordWire` document
  (the supervisor's merge fan-out parses it straight back into a domain record).
* ``apply_annotations`` — mutating; takes a (merged) wire record, parses it once at
  this boundary via :mod:`idamesh.application.annotation_wire`, applies it, and
  reports the ``{applied:{names,comments,types}, ok, failures}`` tally.

The record wire shape is defined once in :mod:`idamesh.application.annotation_wire`
and reused verbatim; only the ``ApplyAnnotationsView`` result projection is local.
"""

from __future__ import annotations

from typing import Any, List, Mapping, Optional, TypedDict

from idamesh.application.annotation_wire import (
    AnnotationRecordWire,
    annotation_record_from_wire,
    annotation_record_to_wire,
)
from idamesh.application.contexts.annotations import (
    ApplyAnnotationsUseCase,
    ExportAnnotationsUseCase,
)
from idamesh.application.dto.annotations import (
    ApplyAnnotationsCommand,
    ExportAnnotationsCommand,
)
from idamesh.domain.entities.annotations import AnnotationApplyReport
from idamesh.domain.ports.execution import MainThreadExecutor
from idamesh.interface.catalog._support import run_mutation, run_use_case
from idamesh.interface.mcp.registry import Registry


class AppliedCountsView(TypedDict):
    """Per-field applied counts of one ``apply_annotations`` call."""

    names: int
    comments: int
    types: int


class ApplyAnnotationsView(TypedDict):
    """The outcome of one ``apply_annotations`` call."""

    applied: AppliedCountsView
    ok: bool
    failures: List[str]


def apply_view(report: AnnotationApplyReport) -> ApplyAnnotationsView:
    """Project an :class:`AnnotationApplyReport` into its wire shape."""
    return ApplyAnnotationsView(
        applied=AppliedCountsView(
            names=report.names,
            comments=report.comments,
            types=report.types,
        ),
        ok=report.ok,
        failures=list(report.failures),
    )


def register_export_annotations(
    registry: Registry,
    *,
    export_annotations_use_case: ExportAnnotationsUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``export_annotations`` (read-only) against the export use-case."""

    @registry.tool(name="export_annotations")
    def export_annotations(
        funcs: Optional[List[str]] = None, include_types: bool = True
    ) -> AnnotationRecordWire:
        """Export this database's user annotations as a portable record. Returns
        the user names, line/function comments, and (when ``include_types``)
        prototypes the user set, each keyed by effective address, plus a
        ``provenance`` block (input path, SHA-256, imagebase, IDA version) that
        identifies the binary. ``funcs`` optionally restricts the export to the
        given functions — each a hex literal (``0x…``), decimal literal, or symbol
        name — resolved first; omit it to export the whole database. This is the
        source half of the merge-back and is read-only. An unresolvable selector
        yields an error result rather than failing the protocol request."""
        command = ExportAnnotationsCommand(
            funcs=tuple(funcs) if funcs is not None else None,
            include_types=include_types,
        )
        result = run_use_case(
            executor, lambda: export_annotations_use_case.execute(command)
        )
        return annotation_record_to_wire(result.record)


def register_apply_annotations(
    registry: Registry,
    *,
    apply_annotations_use_case: ApplyAnnotationsUseCase,
    executor: MainThreadExecutor,
) -> None:
    """Register ``apply_annotations`` (mutating) against the apply use-case."""

    @registry.tool(name="apply_annotations")
    @registry.mutating
    def apply_annotations(record: Mapping[str, Any]) -> ApplyAnnotationsView:
        """Apply a previously exported (or merged) annotation record into this
        database. ``record`` is an annotation document in the shape
        ``export_annotations`` returns — ``provenance`` plus ``names`` /
        ``comments`` / ``prototypes`` entry lists. Each item is written
        best-effort: an item the database refuses (a bad identifier, an unparsable
        prototype, a function comment at a non-function address) is collected into
        ``failures`` rather than aborting the whole apply. The result reports the
        per-field ``applied`` counts, ``ok`` (true when nothing was refused), and
        the ``failures`` list. This modifies the database."""
        parsed = annotation_record_from_wire(record)
        command = ApplyAnnotationsCommand(record=parsed)
        result = run_mutation(
            executor, lambda: apply_annotations_use_case.execute(command)
        )
        return apply_view(result.report)
