"""The outcome entity of applying a merged annotation record.

``apply_annotations`` writes a reconciled :class:`~idamesh.domain.services.reconciliation.AnnotationRecord`
back into one copy, item by item, and reports how much landed.
:class:`AnnotationApplyReport` is that tally: the per-field applied counts plus the
list of individual items the SDK refused (a bad identifier, an unparsable
prototype, a function comment at a non-function address). The apply is
best-effort — a single item's failure is collected here, never aborting the whole
write — so ``ok`` means *no item failed*, and a partial apply still returns a
report rather than raising. The field set is the interoperability fact; the
projection to the ``{applied, ok, failures}`` wire shape is the interface layer's.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Tuple


@dataclass(frozen=True)
class AnnotationApplyReport:
    """How many annotations of each class were applied, and what was refused."""

    #: Count of user names successfully installed.
    names: int = 0
    #: Count of comment slots successfully written.
    comments: int = 0
    #: Count of prototypes/types successfully applied.
    types: int = 0
    #: Human-readable one-liners for the items the database refused.
    failures: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        """``True`` when every item applied cleanly (no collected failure)."""
        return not self.failures

    @property
    def applied(self) -> int:
        """Total annotations successfully applied across all three classes."""
        return self.names + self.comments + self.types
