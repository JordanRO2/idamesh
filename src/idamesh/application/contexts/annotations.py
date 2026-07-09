"""The ``export_annotations`` / ``apply_annotations`` use-cases.

Two thin orchestrations over the :class:`~idamesh.domain.ports.annotations.AnnotationGateway`:

* :class:`ExportAnnotationsUseCase` resolves any function selectors against the
  database gateway (mirroring the read tools), then asks the gateway to export the
  record for those functions (or the whole database).
* :class:`ApplyAnnotationsUseCase` hands the already-parsed record straight to the
  gateway's best-effort apply and wraps the resulting report.

Selector resolution is the only application-level logic here; everything that
touches the SDK lives in the adapter; the
resolution/wrapping below is the frozen seam the merge orchestrator relies on.
"""

from __future__ import annotations

from typing import List

from idamesh.application.dto.annotations import (
    ApplyAnnotationsCommand,
    ApplyAnnotationsResult,
    ExportAnnotationsCommand,
    ExportAnnotationsResult,
)
from idamesh.domain.ports.annotations import AnnotationGateway
from idamesh.domain.ports.database import DatabaseGateway
from idamesh.domain.values.address import Selector


class ExportAnnotationsUseCase:
    """Resolve the optional function filter and export this copy's annotations."""

    def __init__(
        self, annotations: AnnotationGateway, database: DatabaseGateway
    ) -> None:
        self._annotations = annotations
        self._database = database

    def execute(
        self, command: ExportAnnotationsCommand
    ) -> ExportAnnotationsResult:
        """Export the record for ``command``'s functions (or the whole database).

        Each selector in ``command.funcs`` is parsed and resolved to an effective
        address before the gateway reads; ``None`` leaves the filter open. An
        unresolvable selector surfaces as an error the interface layer renders as
        an ``isError`` result.
        """
        eas = self._resolve_funcs(command)
        record = self._annotations.export(
            funcs=eas, include_types=command.include_types
        )
        return ExportAnnotationsResult(record=record)

    def _resolve_funcs(self, command: ExportAnnotationsCommand):
        if command.funcs is None:
            return None
        eas: List[int] = []
        for selector in command.funcs:
            eas.append(int(self._database.resolve(Selector.parse(selector))))
        return eas


class ApplyAnnotationsUseCase:
    """Apply a merged record into this copy and report what landed."""

    def __init__(self, annotations: AnnotationGateway) -> None:
        self._annotations = annotations

    def execute(self, command: ApplyAnnotationsCommand) -> ApplyAnnotationsResult:
        """Apply ``command.record`` best-effort and wrap the apply tally."""
        report = self._annotations.apply(command.record)
        return ApplyAnnotationsResult(report=report)
