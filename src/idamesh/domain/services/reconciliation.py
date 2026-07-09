"""Pure annotation merge-back reconciliation (domain service, IDA-free).

When N agents each edit their own private copy of a binary, ``idb_merge``
consolidates the divergent *user* annotations into one canonical database. The
reconciliation itself — enumerate, baseline-subtract, detect same-address
conflicts, apply a policy, emit an apply-plan + a dry-run report — is a pure
function of the exported records: no IDA, no I/O. That is why it lives in the
domain and can run inside the idapro-free supervisor. Only extraction/apply/
snapshot (which do touch the SDK) live in the worker.

Algorithm:

1. Enumerate the participating session records (deterministic order).
2. Provenance check — refuse if ``input_sha256`` / ``imagebase`` disagree.
3. Baseline subtraction — drop every ``(key, signature)`` byte-identical to a
   pristine re-analysis, so auto-analysis names are not mistaken for user edits.
4. Build the plan — per ``(field, key)``: agreement/singleton auto-resolves;
   two+ distinct values is a Conflict resolved by ``ConflictPolicy``.
5. Emit ``MergePlan`` + the conflict list (the dry-run review gate).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


class ConflictPolicy(str, enum.Enum):
    """How a same-address divergence between two humans is resolved."""

    MANUAL = "manual"
    FIRST = "first"
    LAST = "last"
    PREFER = "prefer"


@dataclass(frozen=True)
class Provenance:
    """Identifies the binary a record was extracted from (the merge safety gate)."""

    input_path: str
    input_sha256: Optional[str] = None
    imagebase: Optional[int] = None
    ida_version: Optional[str] = None


@dataclass(frozen=True)
class AnnotationRecord:
    """One copy's exported user annotations, keyed for reconciliation.

    Each field maps an opaque hashable key (e.g. ``ea`` or ``(ea, scope)``) to a
    hashable *signature* (a name string; a ``(regular, repeatable)`` tuple for
    comments; a type string for prototypes). Empty signatures are ignored.
    """

    provenance: Provenance
    names: Mapping[Any, Any] = field(default_factory=dict)
    comments: Mapping[Any, Any] = field(default_factory=dict)
    prototypes: Mapping[Any, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Conflict:
    """A same-``(field, key)`` divergence with the per-session candidate values."""

    field: str
    key: Any
    candidates: Mapping[str, Any]
    resolved: Optional[Any] = None


@dataclass(frozen=True)
class MergePlan:
    """The reconciled, apply-ready annotations plus the unresolved conflicts."""

    names: Mapping[Any, Any] = field(default_factory=dict)
    comments: Mapping[Any, Any] = field(default_factory=dict)
    prototypes: Mapping[Any, Any] = field(default_factory=dict)
    conflicts: Sequence[Conflict] = field(default_factory=tuple)

    @property
    def counts(self) -> Dict[str, int]:
        """``{names, comments, prototypes, conflicts}`` sizes for the report."""
        return {
            "names": len(self.names),
            "comments": len(self.comments),
            "prototypes": len(self.prototypes),
            "conflicts": len(self.conflicts),
        }


class ProvenanceMismatch(ValueError):
    """Raised when records disagree on the binary they describe (hard gate)."""


#: The three annotation fields reconciled, in their deterministic report order.
_FIELDS: Tuple[str, ...] = ("names", "comments", "prototypes")

#: Sentinel returned by :func:`_resolve_conflict` when a policy leaves a
#: divergence unresolved (so it is reported but never written into the plan).
_UNRESOLVED = object()


def reconcile(
    records: Sequence[Tuple[str, AnnotationRecord]],
    *,
    baseline: Optional[AnnotationRecord] = None,
    baselines: Optional[Mapping[str, AnnotationRecord]] = None,
    policy: ConflictPolicy = ConflictPolicy.MANUAL,
    prefer: Optional[str] = None,
    fields: Optional[Sequence[str]] = None,
) -> MergePlan:
    """Reconcile ``(session_id, record)`` pairs into a :class:`MergePlan`.

    The pipeline is provenance-check → baseline-subtract → per-``(field, key)``
    agreement/conflict detection → policy resolution, and it is pure and
    deterministic: the plan maps and the conflict list are emitted in a stable
    ``(field, sorted key)`` order regardless of input ordering, while the
    *contribution* order used by the ``FIRST``/``LAST`` policies follows the given
    ``records`` sequence.

    ``records`` is a sequence of ``(session_id, AnnotationRecord)`` pairs. Baseline
    subtraction drops every ``(key, signature)`` byte-identical to a pristine
    re-analysis, so unedited auto-analysis / loader symbol names never masquerade
    as human edits. Two baseline forms are supported, ``baselines`` taking
    precedence per session:

    * ``baselines`` — a ``{session_id: AnnotationRecord}`` map of **per-source**
      pristine baselines. Each source is subtracted against *its own* baseline
      (captured from the identical in-process analysis at open, before any edit),
      so the subtraction has zero cross-copy variance — the deterministic path.
    * ``baseline`` — a single shared baseline applied to every source that has no
      entry in ``baselines``. A separately-analyzed copy is not bit-identical to a
      source, so this can leak a few false edits; kept for the pure-domain tests
      and as a fallback.

    For each field, a key whose non-empty candidate values all agree (or where only
    one session contributes one) is auto-resolved into the plan; two or more
    distinct non-empty values form a :class:`Conflict` resolved under ``policy``:

    * ``MANUAL`` — left unresolved (reported, not written).
    * ``FIRST`` / ``LAST`` — the earliest / latest contributing session wins.
    * ``PREFER`` — ``prefer``'s value wins when it contributed one, else the
      conflict is left unresolved.

    Every divergence is recorded in :attr:`MergePlan.conflicts` (with its
    per-session ``candidates`` and the ``resolved`` value, which is ``None`` when
    unresolved); only resolved values are also written into the plan maps.

    ``fields`` optionally restricts reconciliation to a subset of
    ``{"names", "comments", "prototypes"}`` (``None`` selects all three; an empty
    sequence selects none). Raises :class:`ProvenanceMismatch` when the records
    (or any baseline) disagree on ``input_sha256`` or ``imagebase``, and
    ``ValueError`` on an unknown field name.
    """
    selected = _select_fields(fields)
    pairs: List[Tuple[str, AnnotationRecord]] = [
        (str(session_id), record) for session_id, record in records
    ]
    per_source: Dict[str, AnnotationRecord] = (
        {str(sid): record for sid, record in baselines.items()} if baselines else {}
    )
    _check_provenance(pairs, baseline, per_source)

    plan_maps: Dict[str, Dict[Any, Any]] = {name: {} for name in _FIELDS}
    conflicts: List[Conflict] = []
    for field_name in _FIELDS:
        if field_name not in selected:
            continue
        field_map, field_conflicts = _reconcile_field(
            field_name, pairs, baseline, per_source, policy, prefer
        )
        plan_maps[field_name] = field_map
        conflicts.extend(field_conflicts)

    return MergePlan(
        names=plan_maps["names"],
        comments=plan_maps["comments"],
        prototypes=plan_maps["prototypes"],
        conflicts=tuple(conflicts),
    )


def plan_to_record(
    plan: MergePlan, provenance: Optional[Provenance] = None
) -> AnnotationRecord:
    """Serialize a reconciled :class:`MergePlan` back into an applyable record.

    The returned :class:`AnnotationRecord` carries only the merge plan's resolved
    entries (auto-resolved agreements/singletons plus policy-resolved conflicts);
    unresolved conflicts are absent by construction. ``provenance`` tags the merged
    record — callers pass the target copy's provenance — and defaults to an empty
    placeholder because the apply step never keys off it.
    """
    return AnnotationRecord(
        provenance=provenance if provenance is not None else Provenance(input_path=""),
        names=dict(plan.names),
        comments=dict(plan.comments),
        prototypes=dict(plan.prototypes),
    )


def dry_run_report(plan: MergePlan) -> Dict[str, Any]:
    """Render the review-gate view of a plan: merged counts + the full conflict list.

    This is the pure core of ``idb_merge``'s ``dry_run`` output — the supervisor
    wraps it with the session-reachability fields it alone knows. Each conflict is
    expanded to ``{field, key, ea, candidates, resolved}``; ``ea`` is derived from
    the key when it is (or begins with) an integer effective address, else
    ``None``.
    """
    return {
        "merged_counts": dict(plan.counts),
        "conflicts": [_conflict_to_dict(conflict) for conflict in plan.conflicts],
    }


# -- internals -------------------------------------------------------------- #


def _select_fields(fields: Optional[Sequence[str]]) -> "set[str]":
    """Validate and resolve the requested field subset (``None`` selects all)."""
    if fields is None:
        return set(_FIELDS)
    selected: "set[str]" = set()
    for name in fields:
        if name not in _FIELDS:
            raise ValueError(
                f"unknown merge field {name!r}; choose from {list(_FIELDS)}"
            )
        selected.add(name)
    return selected


def _check_provenance(
    pairs: Sequence[Tuple[str, AnnotationRecord]],
    baseline: Optional[AnnotationRecord],
    per_source: Optional[Mapping[str, AnnotationRecord]] = None,
) -> None:
    """Reject a merge whose records describe different binaries or rebased images."""
    provenances: List[Provenance] = [record.provenance for _, record in pairs]
    if baseline is not None:
        provenances.append(baseline.provenance)
    for record in (per_source or {}).values():
        provenances.append(record.provenance)
    for attr in ("input_sha256", "imagebase"):
        values = {
            getattr(prov, attr)
            for prov in provenances
            if getattr(prov, attr) is not None
        }
        if len(values) > 1:
            rendered = ", ".join(sorted(repr(value) for value in values))
            raise ProvenanceMismatch(
                f"records disagree on {attr} ({rendered}); refusing to merge "
                "EA-keyed annotations across different binaries"
            )


def _reconcile_field(
    field_name: str,
    pairs: Sequence[Tuple[str, AnnotationRecord]],
    baseline: Optional[AnnotationRecord],
    per_source: Mapping[str, AnnotationRecord],
    policy: ConflictPolicy,
    prefer: Optional[str],
) -> Tuple[Dict[Any, Any], List[Conflict]]:
    """Reconcile one field into ``(plan_map, conflicts)`` (both deterministic).

    Each source is subtracted against its own baseline when ``per_source`` carries
    one for its session id, otherwise against the shared ``baseline`` — so the
    per-session pristine baselines and the legacy single baseline coexist.
    """
    shared_map: Mapping[Any, Any] = (
        getattr(baseline, field_name) if baseline is not None else {}
    ) or {}

    # key -> ordered [(session_id, signature)] of genuine (non-baseline) edits.
    candidates: Dict[Any, List[Tuple[str, Any]]] = {}
    for session_id, record in pairs:
        source_baseline = per_source.get(session_id)
        baseline_map: Mapping[Any, Any] = (
            (getattr(source_baseline, field_name) or {})
            if source_baseline is not None
            else shared_map
        )
        field_data: Mapping[Any, Any] = getattr(record, field_name) or {}
        for key, signature in field_data.items():
            if _is_empty_signature(signature):
                continue
            if key in baseline_map and baseline_map[key] == signature:
                continue  # byte-identical to this source's pristine baseline → not an edit
            candidates.setdefault(key, []).append((session_id, signature))

    plan_map: Dict[Any, Any] = {}
    conflicts: List[Conflict] = []
    for key in _sorted_keys(candidates):
        entries = candidates[key]
        distinct = _distinct_signatures(entries)
        if len(distinct) == 1:
            plan_map[key] = distinct[0]  # unanimous agreement or lone contributor
            continue
        candidate_map = {session_id: signature for session_id, signature in entries}
        resolved = _resolve_conflict(entries, policy, prefer)
        if resolved is _UNRESOLVED:
            conflicts.append(Conflict(field_name, key, candidate_map, None))
        else:
            plan_map[key] = resolved
            conflicts.append(Conflict(field_name, key, candidate_map, resolved))
    return plan_map, conflicts


def _resolve_conflict(
    entries: Sequence[Tuple[str, Any]],
    policy: ConflictPolicy,
    prefer: Optional[str],
) -> Any:
    """Pick a winning signature for a divergence, or ``_UNRESOLVED``."""
    if policy is ConflictPolicy.FIRST:
        return entries[0][1]
    if policy is ConflictPolicy.LAST:
        return entries[-1][1]
    if policy is ConflictPolicy.PREFER:
        for session_id, signature in entries:
            if session_id == prefer:
                return signature
        return _UNRESOLVED
    return _UNRESOLVED  # MANUAL — leave it for the human review gate


def _distinct_signatures(entries: Sequence[Tuple[str, Any]]) -> List[Any]:
    """First-seen-ordered unique signatures (equality, hashability-agnostic)."""
    seen: List[Any] = []
    for _, signature in entries:
        if signature not in seen:
            seen.append(signature)
    return seen


def _sorted_keys(mapping: Mapping[Any, Any]) -> List[Any]:
    """Deterministically ordered keys, tolerating unorderable/mixed key types."""
    keys = list(mapping.keys())
    try:
        return sorted(keys)
    except TypeError:
        return sorted(keys, key=repr)


def _is_empty_signature(signature: Any) -> bool:
    """A signature carrying no annotation (dropped from candidates)."""
    if signature is None:
        return True
    if isinstance(signature, str):
        return signature == ""
    if isinstance(signature, (tuple, list)):
        return all(_is_empty_signature(part) for part in signature)
    return False


def _conflict_to_dict(conflict: Conflict) -> Dict[str, Any]:
    """Expand a :class:`Conflict` into the dry-run report's per-item shape."""
    return {
        "field": conflict.field,
        "key": conflict.key,
        "ea": _ea_of(conflict.key),
        "candidates": dict(conflict.candidates),
        "resolved": conflict.resolved,
    }


def _ea_of(key: Any) -> Optional[int]:
    """The effective address a key encodes, when it is an int or starts with one."""
    if isinstance(key, bool):
        return None
    if isinstance(key, int):
        return key
    if isinstance(key, tuple) and key and isinstance(key[0], int) and not isinstance(
        key[0], bool
    ):
        return key[0]
    return None


__all__ = [
    "ConflictPolicy",
    "Provenance",
    "AnnotationRecord",
    "Conflict",
    "MergePlan",
    "ProvenanceMismatch",
    "reconcile",
    "plan_to_record",
    "dry_run_report",
]
