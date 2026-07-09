"""The one wire projection of a domain :class:`AnnotationRecord` (shared contract).

The merge-back moves annotations across a process boundary three times — a worker
*exports* its record, the supervisor *reconciles* the exported records, and a
worker *applies* the merged record — so the JSON shape those hops speak has to be
frozen in exactly one place. That place is here. The pure reconciliation engine in
:mod:`idamesh.domain.services.reconciliation` keys and signs annotations with
Python-native (and unhashable-in-JSON) values: an ``ea`` integer key, a name
string, a ``(regular, repeatable)`` comment tuple, a ``(ea, scope)`` composite
key. This module is the single bijection between those domain values and a plain,
list-of-objects JSON document that survives ``json.dumps`` and an MCP round-trip.

Living in ``application`` (not ``interface``) lets both the worker tool catalog
(``export_annotations`` projects, ``apply_annotations`` parses) and the
idapro-free supervisor merge orchestrator (parses each worker's export, projects
the merged plan back for apply) share it without either importing the other, and
without the SDK anywhere in sight.

Wire shape (the frozen ``AnnotationRecordWire``)::

    {
      "provenance": {"input_path", "input_sha256"?, "imagebase"?, "ida_version"?},
      "names":      [{"ea": int, "name": str}, ...],
      "comments":   [{"ea": int, "scope": str, "regular": str, "repeatable": str}],
      "prototypes": [{"ea": int, "type": str}, ...]
    }

The domain key/signature conventions this file freezes:

* **names** — key ``ea`` (int), signature the name string.
* **comments** — key ``(ea, scope)`` with ``scope`` in :data:`COMMENT_SCOPES`,
  signature the ``(regular, repeatable)`` string pair.
* **prototypes** — key ``ea`` (int), signature the C type string.

The design doc's per-item ``kind`` (func/data) is deliberately *not* on the wire:
the reconciliation is keyed and signed without it and the merged record is applied
without it, so carrying it would be a value the domain record has no slot for and
the apply path never reads. Entry lists are emitted in ascending ``(ea, scope)``
order so a projection is deterministic regardless of source dict ordering.
"""

from __future__ import annotations

from typing import Any, List, Mapping, Optional, Tuple

try:  # Python 3.11+: NotRequired makes optional TypedDict keys explicit.
    from typing import NotRequired  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - 3.9 / 3.10 fallback
    NotRequired = None  # type: ignore[assignment]

from typing import TypedDict

from idamesh.domain.services.reconciliation import AnnotationRecord, Provenance

#: The comment scopes the ``(ea, scope)`` key admits: the line/item comment
#: (``ida_bytes.get_cmt``) and the enclosing-function comment
#: (``ida_funcs.get_func_cmt``).
COMMENT_SCOPES: Tuple[str, ...] = ("line", "func")


class ProvenanceWire(TypedDict):
    """JSON view of :class:`~idamesh.domain.services.reconciliation.Provenance`."""

    input_path: str
    input_sha256: Optional[str]
    imagebase: Optional[int]
    ida_version: Optional[str]


class NameEntryWire(TypedDict):
    """One user name: the ``ea`` it sits at and the name string."""

    ea: int
    name: str


class CommentEntryWire(TypedDict):
    """One comment: its ``ea``, ``scope``, and the regular/repeatable text pair."""

    ea: int
    scope: str
    regular: str
    repeatable: str


class PrototypeEntryWire(TypedDict):
    """One applied prototype/type: the ``ea`` and its C declaration string."""

    ea: int
    type: str


class AnnotationRecordWire(TypedDict):
    """The frozen JSON projection of a domain :class:`AnnotationRecord`."""

    provenance: ProvenanceWire
    names: List[NameEntryWire]
    comments: List[CommentEntryWire]
    prototypes: List[PrototypeEntryWire]


# -- provenance ------------------------------------------------------------- #


def provenance_to_wire(provenance: Provenance) -> ProvenanceWire:
    """Project a :class:`Provenance` into its JSON object."""
    return ProvenanceWire(
        input_path=provenance.input_path,
        input_sha256=provenance.input_sha256,
        imagebase=provenance.imagebase,
        ida_version=provenance.ida_version,
    )


def provenance_from_wire(wire: Optional[Mapping[str, Any]]) -> Provenance:
    """Parse a provenance JSON object (``None``/missing → empty placeholder)."""
    data = dict(wire or {})
    return Provenance(
        input_path=str(data.get("input_path", "") or ""),
        input_sha256=_opt_str(data.get("input_sha256")),
        imagebase=_opt_int(data.get("imagebase")),
        ida_version=_opt_str(data.get("ida_version")),
    )


# -- record ----------------------------------------------------------------- #


def annotation_record_to_wire(record: AnnotationRecord) -> AnnotationRecordWire:
    """Project a domain :class:`AnnotationRecord` into the frozen wire document."""
    names: List[NameEntryWire] = [
        NameEntryWire(ea=int(ea), name=str(name))
        for ea, name in _sorted_by_ea(record.names)
    ]
    comments: List[CommentEntryWire] = []
    for key, signature in _sorted_comment_items(record.comments):
        ea, scope = _split_comment_key(key)
        regular, repeatable = _split_comment_signature(signature)
        comments.append(
            CommentEntryWire(
                ea=int(ea),
                scope=str(scope),
                regular=regular,
                repeatable=repeatable,
            )
        )
    prototypes: List[PrototypeEntryWire] = [
        PrototypeEntryWire(ea=int(ea), type=str(decl))
        for ea, decl in _sorted_by_ea(record.prototypes)
    ]
    return AnnotationRecordWire(
        provenance=provenance_to_wire(record.provenance),
        names=names,
        comments=comments,
        prototypes=prototypes,
    )


def annotation_record_from_wire(wire: Mapping[str, Any]) -> AnnotationRecord:
    """Parse a wire document into a domain :class:`AnnotationRecord`.

    Reconstructs the exact key/signature conventions :func:`reconcile` expects:
    integer ``ea`` keys, ``(ea, scope)`` comment keys, and ``(regular,
    repeatable)`` tuple comment signatures. Malformed entries (missing ``ea``,
    non-object items) are skipped rather than fatal, so one bad row never poisons a
    whole merge.
    """
    names = {}
    for entry in _entries(wire, "names"):
        ea = _opt_int(entry.get("ea"))
        if ea is None:
            continue
        names[ea] = str(entry.get("name", "") or "")
    comments = {}
    for entry in _entries(wire, "comments"):
        ea = _opt_int(entry.get("ea"))
        if ea is None:
            continue
        scope = str(entry.get("scope", "") or "")
        comments[(ea, scope)] = (
            str(entry.get("regular", "") or ""),
            str(entry.get("repeatable", "") or ""),
        )
    prototypes = {}
    for entry in _entries(wire, "prototypes"):
        ea = _opt_int(entry.get("ea"))
        if ea is None:
            continue
        prototypes[ea] = str(entry.get("type", "") or "")
    return AnnotationRecord(
        provenance=provenance_from_wire(wire.get("provenance")),
        names=names,
        comments=comments,
        prototypes=prototypes,
    )


# -- internals -------------------------------------------------------------- #


def _entries(wire: Mapping[str, Any], field: str) -> List[Mapping[str, Any]]:
    """The list of object entries under ``field`` (non-objects filtered out)."""
    raw = wire.get(field)
    if not isinstance(raw, (list, tuple)):
        return []
    return [entry for entry in raw if isinstance(entry, Mapping)]


def _sorted_by_ea(mapping: Mapping[Any, Any]) -> List[Tuple[Any, Any]]:
    """``(ea, value)`` pairs in ascending ea order (repr fallback for odd keys)."""
    items = list(mapping.items())
    try:
        return sorted(items, key=lambda kv: kv[0])
    except TypeError:  # pragma: no cover - defensive against mixed key types
        return sorted(items, key=lambda kv: repr(kv[0]))


def _sorted_comment_items(mapping: Mapping[Any, Any]) -> List[Tuple[Any, Any]]:
    """Comment ``(key, signature)`` pairs in ascending ``(ea, scope)`` order."""
    items = list(mapping.items())
    try:
        return sorted(items, key=lambda kv: _split_comment_key(kv[0]))
    except TypeError:  # pragma: no cover - defensive
        return sorted(items, key=lambda kv: repr(kv[0]))


def _split_comment_key(key: Any) -> Tuple[int, str]:
    """Decompose a comment key into ``(ea, scope)`` (tolerates a bare ea)."""
    if isinstance(key, (tuple, list)) and len(key) >= 2:
        return int(key[0]), str(key[1])
    return int(key), ""


def _split_comment_signature(signature: Any) -> Tuple[str, str]:
    """Decompose a comment signature into ``(regular, repeatable)`` strings."""
    if isinstance(signature, (tuple, list)):
        regular = signature[0] if len(signature) > 0 else ""
        repeatable = signature[1] if len(signature) > 1 else ""
    else:
        regular, repeatable = signature, ""
    return _str_or_empty(regular), _str_or_empty(repeatable)


def _str_or_empty(value: Any) -> str:
    return "" if value is None else str(value)


def _opt_str(value: Any) -> Optional[str]:
    return None if value is None else str(value)


def _opt_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


__all__ = [
    "COMMENT_SCOPES",
    "ProvenanceWire",
    "NameEntryWire",
    "CommentEntryWire",
    "PrototypeEntryWire",
    "AnnotationRecordWire",
    "provenance_to_wire",
    "provenance_from_wire",
    "annotation_record_to_wire",
    "annotation_record_from_wire",
]
