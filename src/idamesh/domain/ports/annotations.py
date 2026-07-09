"""The annotation gateway port: export and apply user annotations.

This is the IDA-side half of the merge-back, kept behind a port so the pure
reconciliation and the orchestration never see the SDK. One gateway serves both
worker tools:

* :meth:`export` reads *this copy's* user annotations — names the user set
  (``has_user_name`` gate), line/function comments, and prototypes — into a domain
  :class:`~idamesh.domain.services.reconciliation.AnnotationRecord`, tagged with a
  :class:`~idamesh.domain.services.reconciliation.Provenance` block (input path,
  SHA-256, imagebase, IDA version) so the reconciler can gate a merge on binary
  identity.
* :meth:`apply` writes a (merged) record back into this copy, best-effort per item,
  returning an :class:`~idamesh.domain.entities.annotations.AnnotationApplyReport`.

The signatures are frozen here so the export/apply use-cases and the merge
orchestrator compile against them; the adapter under ``infrastructure/ida`` fills
the SDK bodies with all ``ida_*`` imports lazy.
"""

from __future__ import annotations

from typing import Optional, Protocol, Sequence

from idamesh.domain.entities.annotations import AnnotationApplyReport
from idamesh.domain.services.reconciliation import AnnotationRecord


class AnnotationGateway(Protocol):
    """Read/write access to the user annotations of the open database."""

    def export(
        self,
        *,
        funcs: Optional[Sequence[int]] = None,
        include_types: bool = True,
    ) -> AnnotationRecord:
        """Export this copy's user annotations into an :class:`AnnotationRecord`.

        ``funcs`` optionally restricts the export to the given function effective
        addresses (``None`` covers the whole database); ``include_types`` toggles
        the (comparatively expensive) prototype/type read. The returned record's
        ``provenance`` identifies the binary the annotations came from so a later
        merge can refuse to reconcile across different inputs.
        """
        ...

    def apply(self, record: AnnotationRecord) -> AnnotationApplyReport:
        """Apply ``record``'s annotations into this copy, best-effort per item.

        Installs each name/comment/prototype, collecting rather than raising on an
        item the database refuses, and returns the per-field applied counts plus
        the collected failures. The record's ``provenance`` is not consulted — the
        caller is responsible for having gated identity before applying.
        """
        ...
