"""The ``idb_merge`` orchestration — supervisor-side, idapro-free.

``idb_merge`` is the capstone: N agents edit their own private copies in parallel,
then this reconciles their divergent user annotations into one canonical database.
It is a *management* tool the supervisor runs itself (it never routes to a single
worker), and it is strictly idapro-free — the only SDK work is delegated to the
worker tools ``export_annotations`` / ``apply_annotations`` / ``idb_snapshot``,
reached over the injected :class:`WorkerClientPort`. The reconciliation math is the
pure domain service :func:`~idamesh.domain.services.reconciliation.reconcile`.

Pipeline::

    resolve sources → export(each) → subtract each source's own pristine baseline
        → reconcile(policy) → dry_run report  |  apply(into) + snapshot → applied

Baselines are **per session**: each copy's unedited annotation record is captured
in-process at ``idb_open`` (:meth:`capture_pristine_baseline`, driven by the
supervisor) and stored on the session. At merge time each source is subtracted
against *its own* baseline, so the subtraction shares the source's identical
in-process analysis and carries zero cross-copy variance — the deterministic
replacement for the old shared fresh-baseline-worker spawn, which was a separate
idalib process whose auto-analysis was not bit-identical and leaked false edits.

The worker-touching steps are isolated in clearly-named seam methods
(``_resolve_sources``, ``_export_all``, ``_gather_baselines``,
``capture_pristine_baseline``, ``_apply``, ``_snapshot``), wired against the ports
so the whole pipeline runs end to end against a fake pool / client.
"""

from __future__ import annotations

import itertools
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from idamesh.application.annotation_wire import (
    annotation_record_from_wire,
    annotation_record_to_wire,
)
from idamesh.domain.services.reconciliation import (
    AnnotationRecord,
    ConflictPolicy,
    Provenance,
    ProvenanceMismatch,
    dry_run_report,
    plan_to_record,
    reconcile,
)
from idamesh.interface.router.ports import (
    SessionView,
    WorkerClientPort,
    WorkerPoolPort,
)

#: The worker tools the orchestrator drives over the client (never local).
_EXPORT_TOOL = "export_annotations"
_APPLY_TOOL = "apply_annotations"
_SNAPSHOT_TOOL = "idb_snapshot"

#: The pristine-baseline export runs immediately after a worker's readiness
#: handshake; a transient connection blip there must not leave a session without
#: its baseline (which forces a merge refusal), so the capture is retried.
_BASELINE_CAPTURE_ATTEMPTS = 3
_BASELINE_CAPTURE_BACKOFF = 0.2

#: Suffix of the canonical merged database written by an applied merge.
_MERGED_SUFFIX = ".merged.i64"


class MergeError(RuntimeError):
    """A merge could not proceed for an operational reason (bad args, no sources)."""


@dataclass(frozen=True)
class MergeRequest:
    """The parsed, validated ``idb_merge`` arguments."""

    sources: Tuple[str, ...] = ()
    path: str = ""
    into: str = ""
    policy: ConflictPolicy = ConflictPolicy.MANUAL
    prefer: str = ""
    fields: Optional[Tuple[str, ...]] = None
    dry_run: bool = False
    use_baseline: bool = True

    @classmethod
    def from_args(cls, args: Mapping[str, Any]) -> "MergeRequest":
        """Parse a raw ``arguments`` object into a :class:`MergeRequest`.

        Raises :class:`MergeError` on a malformed policy or a request that names
        neither explicit ``sources`` nor a ``path`` to enumerate.
        """
        sources = _str_tuple(args.get("sources"))
        path = _as_str(args.get("path"))
        into = _as_str(args.get("into"))
        prefer = _as_str(args.get("prefer"))
        raw_policy = (_as_str(args.get("policy")) or ConflictPolicy.MANUAL.value).lower()
        try:
            policy = ConflictPolicy(raw_policy)
        except ValueError as exc:
            allowed = ", ".join(p.value for p in ConflictPolicy)
            raise MergeError(
                f"unknown merge policy {raw_policy!r}; choose from {allowed}"
            ) from exc
        raw_fields = args.get("fields")
        fields = _str_tuple(raw_fields) if raw_fields is not None else None
        if not sources and not path:
            raise MergeError(
                "idb_merge needs either 'sources' (explicit session ids) or 'path' "
                "(to enumerate every open copy of that binary)"
            )
        return cls(
            sources=sources,
            path=path,
            into=into,
            policy=policy,
            prefer=prefer,
            fields=fields,
            dry_run=bool(args.get("dry_run", False)),
            use_baseline=bool(args.get("use_baseline", True)),
        )


class MergeOrchestrator:
    """Runs the ``idb_merge`` pipeline against the worker pool and client."""

    def __init__(
        self,
        *,
        pool: WorkerPoolPort,
        client: WorkerClientPort,
    ) -> None:
        self._pool = pool
        self._client = client
        self._inner_ids = itertools.count(1)

    # -- entry point ---------------------------------------------------------

    def merge(self, args: Mapping[str, Any]) -> Dict[str, Any]:
        """Run the merge and return the report payload (never a wire envelope).

        The caller (the supervisor router) wraps the payload in the MCP tool-result
        envelope: a payload carrying an ``error`` key becomes an ``isError`` result,
        anything else a success result. Three payload shapes:

        * **dry-run** — ``{dry_run, sessions, reachable, unreachable, merged_counts,
          conflicts, baseline_sessions?, baseline_missing?}``, writes nothing.
        * **applied** — the same plus ``{ok, dry_run:false, into, applied, failures,
          snapshot}``, where ``ok`` reflects the worker's real apply outcome and
          ``failures`` carries any per-item apply errors it reported.
        * **refused** — ``{error, conflicts?, ...}`` on a source provenance mismatch,
          a write target whose provenance disagrees with the sources', a write-step
          transport/tool failure, or, under ``manual`` policy, an unresolved conflict
          set.
        """
        try:
            request = MergeRequest.from_args(args)
        except MergeError as exc:
            return {"error": str(exc)}

        sessions = self._resolve_sources(request)
        if not sessions:
            return {
                "error": (
                    "no live sessions to merge; open copies with idb_open (list "
                    "them with idb_list) or pass explicit 'sources'"
                ),
                "sessions": [],
                "reachable": [],
                "unreachable": [],
            }

        session_ids = [s.session_id for s in sessions]
        reachable, unreachable, records = self._export_all(sessions)

        # Per-session pristine baselines: each reachable source is subtracted
        # against ITS OWN baseline captured in-process at idb_open (before any
        # edit), so the subtraction has zero cross-copy analysis variance. This
        # replaces the old shared fresh-baseline-worker spawn (a separate idalib
        # process whose auto-analysis is not bit-identical and leaked false edits).
        baselines: Dict[str, AnnotationRecord] = {}
        baseline_sessions: List[str] = []
        baseline_missing: List[str] = []
        if request.use_baseline:
            baselines, baseline_sessions, baseline_missing = self._gather_baselines(
                sessions, records
            )

        try:
            plan = reconcile(
                records,
                baselines=baselines or None,
                policy=request.policy,
                prefer=request.prefer or None,
                fields=list(request.fields) if request.fields is not None else None,
            )
        except ProvenanceMismatch as exc:
            return {
                "error": str(exc),
                "sessions": session_ids,
                "reachable": reachable,
                "unreachable": unreachable,
            }

        report = dry_run_report(plan)
        common: Dict[str, Any] = {
            "sessions": session_ids,
            "reachable": reachable,
            "unreachable": unreachable,
            "merged_counts": report["merged_counts"],
            "conflicts": report["conflicts"],
        }
        if request.use_baseline:
            # Sources whose pristine baseline was subtracted. A source missing its
            # baseline (capture failed even after retries) cannot have its real
            # edits isolated — merging its raw auto-analysis as if it were edits is
            # exactly the non-determinism this design removes — so the merge refuses.
            common["baseline_sessions"] = baseline_sessions
            if baseline_missing:
                common["baseline_missing"] = baseline_missing
                return {
                    "error": (
                        "merge refused: no pristine baseline for "
                        f"{baseline_missing}; their real edits cannot be isolated. "
                        "Reopen those sessions (idb_open captures a fresh baseline) "
                        "and retry, or pass use_baseline=false to merge raw exports."
                    ),
                    **common,
                }

        unresolved = [c for c in plan.conflicts if c.resolved is None]
        if request.dry_run:
            return {"dry_run": True, **common}
        if request.policy is ConflictPolicy.MANUAL and unresolved:
            return {
                "error": (
                    "merge refused: unresolved conflicts under 'manual' policy; "
                    "review them and rerun with policy=first|last|prefer"
                ),
                **common,
            }

        # The write phase — target selection, the cross-binary provenance gate, the
        # apply, and the snapshot — is fully guarded: any operational failure
        # (unreachable target, a worker tool error) yields the same structured
        # ``error`` refusal shape rather than crashing out of ``merge()``.
        try:
            target = self._resolve_target(request, sessions)
            prov_error = self._verify_target_provenance(target, records)
            if prov_error is not None:
                # Cross-binary target: refuse before touching it (no apply, no
                # snapshot). EA-keyed annotations written into the wrong database
                # are silent corruption.
                return {"error": prov_error, **common}
            merged_record = plan_to_record(plan)
            apply_outcome = self._apply(target, merged_record)
            snapshot = self._snapshot(target)
        except MergeError as exc:
            return {"error": str(exc), **common}

        return {
            "ok": apply_outcome["ok"],
            "dry_run": False,
            "into": target.session_id,
            "applied": apply_outcome["applied"],
            "failures": apply_outcome["failures"],
            "snapshot": snapshot,
            **common,
        }

    # -- seams -------------------------------------------

    def _resolve_sources(self, request: MergeRequest) -> List[SessionView]:
        """The live sessions participating in this merge, in deterministic order.

        Explicit ``sources`` ids win (intersected with the live set so a stale id
        drops out); otherwise every live session whose ``input_path`` matches
        ``request.path``. tighten path matching (exact key / resolved
        realpath / basename) — the basename match here is the minimal seam.
        """
        live = list(self._pool.list_sessions())
        if request.sources:
            wanted = list(request.sources)
            by_id = {s.session_id: s for s in live}
            return [by_id[sid] for sid in wanted if sid in by_id]
        return [s for s in live if _path_matches(request.path, s)]

    def _export_all(
        self, sessions: Sequence[SessionView]
    ) -> Tuple[List[str], List[str], List[Tuple[str, AnnotationRecord]]]:
        """Fan ``export_annotations`` out to each session; parse the wire records.

        Returns ``(reachable_ids, unreachable_ids, [(session_id, record)])``. A
        session whose export cannot be reached or returns an error is recorded as
        unreachable and contributes no record (the merge proceeds on the rest).
        """
        reachable: List[str] = []
        unreachable: List[str] = []
        records: List[Tuple[str, AnnotationRecord]] = []
        for session in sessions:
            try:
                structured = self._call_worker_tool(session, _EXPORT_TOOL, {})
            except MergeError:
                unreachable.append(session.session_id)
                continue
            reachable.append(session.session_id)
            records.append(
                (session.session_id, annotation_record_from_wire(structured or {}))
            )
        return reachable, unreachable, records

    def capture_pristine_baseline(
        self, session: SessionView
    ) -> Optional[Mapping[str, Any]]:
        """Export ``session``'s annotations now and store them as its pristine
        baseline (``session.baseline_record``).

        Called by the supervisor immediately after a freshly opened worker becomes
        ready — its initial auto-analysis is complete but no agent has edited yet —
        so the captured record is exactly this copy's unedited auto-analysis/loader
        state, in the *same* in-process analysis its later export will share. That
        is what makes the per-source subtraction at merge time exact and
        deterministic. Idapro-free: it drives the worker's ``export_annotations``
        over the injected client, never the SDK.

        Returns the captured wire record, or ``None`` when the export could not be
        reached — a missing baseline is non-fatal (the merge falls back to keeping
        that source's raw export and reports it under ``baseline_missing``).
        """
        for attempt in range(_BASELINE_CAPTURE_ATTEMPTS):
            try:
                structured = self._call_worker_tool(session, _EXPORT_TOOL, {})
            except MergeError:
                # Transient blip right after the handshake; retry so the session
                # is not left baseline-less (which would force a merge refusal).
                if attempt + 1 < _BASELINE_CAPTURE_ATTEMPTS:
                    time.sleep(_BASELINE_CAPTURE_BACKOFF)
                continue
            wire = dict(structured or {})
            session.baseline_record = wire
            return wire
        return None

    def _gather_baselines(
        self,
        sessions: Sequence[SessionView],
        records: Sequence[Tuple[str, AnnotationRecord]],
    ) -> Tuple[Dict[str, AnnotationRecord], List[str], List[str]]:
        """Collect each reachable source's own pristine baseline for subtraction.

        Reads the baseline captured on the session at ``idb_open`` (no worker is
        opened or spawned here — the whole point of the fix). Returns
        ``(baselines_by_session_id, captured_ids, missing_ids)`` where a source with
        no stored baseline (capture failed, or it predates the capture wiring)
        lands in ``missing_ids`` and is simply left unsubtracted rather than
        subtracted against some other copy's noise.
        """
        by_id = {s.session_id: s for s in sessions}
        baselines: Dict[str, AnnotationRecord] = {}
        captured: List[str] = []
        missing: List[str] = []
        for session_id, _record in records:  # reachable sources only
            session = by_id.get(session_id)
            wire = getattr(session, "baseline_record", None) if session else None
            if wire:
                baselines[session_id] = annotation_record_from_wire(wire)
                captured.append(session_id)
            else:
                missing.append(session_id)
        return baselines, captured, missing

    def _resolve_target(
        self, request: MergeRequest, sessions: Sequence[SessionView]
    ) -> SessionView:
        """The session the merged record is applied into (``into`` or first source).

        validate an explicit ``into`` against the live set and error
        clearly when it names no open session.
        """
        if request.into:
            for session in sessions:
                if session.session_id == request.into:
                    return session
            found = self._pool.get(request.into)
            if found is not None:
                return found
            raise MergeError(
                f"merge target '{request.into}' is not an open session"
            )
        return sessions[0]

    def _verify_target_provenance(
        self,
        target: SessionView,
        records: Sequence[Tuple[str, AnnotationRecord]],
    ) -> Optional[str]:
        """Guard the write target against cross-binary corruption.

        :func:`reconcile` only validated the SOURCE records; the write target
        chosen by :meth:`_resolve_target` may be a session that never participated
        (an explicit ``into`` resolved straight from the pool). Applying EA-keyed
        annotations to a copy of a *different* binary silently corrupts it, so the
        target's provenance must agree with the sources'.

        Returns ``None`` when the target is safe to write, or a structured refusal
        message otherwise. A target that is literally one of the already-validated
        source sessions is trusted without re-exporting. Otherwise its provenance
        is exported and matched against the single sha256 / imagebase the sources
        agreed on (reconcile has already refused any disagreement among those). A
        target whose provenance cannot be *positively confirmed* — its export
        failed, it carries no ``input_sha256`` to match an agreed one, or there is
        no identifying field to verify against at all — is refused rather than
        trusted.
        """
        by_id = {session_id for session_id, _record in records}
        if target.session_id in by_id:
            return None  # already provenance-checked as a participating source

        agreed_sha, agreed_imagebase = _agreed_provenance(records)
        try:
            structured = self._call_worker_tool(target, _EXPORT_TOOL, {})
        except MergeError as exc:
            return (
                f"merge refused: target '{target.session_id}' provenance could not "
                f"be established ({exc}); refusing to write EA-keyed annotations "
                "into a database whose binary cannot be confirmed"
            )
        target_prov = annotation_record_from_wire(structured or {}).provenance

        confirmed = False
        if agreed_sha is not None:
            if target_prov.input_sha256 is None:
                return (
                    f"merge refused: target '{target.session_id}' reports no "
                    f"input_sha256 to match the agreed source sha256 {agreed_sha!r}; "
                    "refusing to write EA-keyed annotations into an unverified binary"
                )
            if target_prov.input_sha256 != agreed_sha:
                return (
                    f"merge refused: target '{target.session_id}' input_sha256 "
                    f"{target_prov.input_sha256!r} != agreed source sha256 "
                    f"{agreed_sha!r}; refusing to write EA-keyed annotations across "
                    "different binaries"
                )
            confirmed = True
        if agreed_imagebase is not None and target_prov.imagebase is not None:
            if target_prov.imagebase != agreed_imagebase:
                return (
                    f"merge refused: target '{target.session_id}' imagebase "
                    f"{target_prov.imagebase!r} != agreed source imagebase "
                    f"{agreed_imagebase!r}; refusing to write rebased EA-keyed "
                    "annotations"
                )
            confirmed = True
        if not confirmed:
            return (
                f"merge refused: target '{target.session_id}' provenance could not "
                "be confirmed against the sources (no matching sha256/imagebase); "
                "refusing to write EA-keyed annotations into an unverified binary"
            )
        return None

    def _apply(
        self, target: SessionView, record: AnnotationRecord
    ) -> Dict[str, Any]:
        """Apply the merged record into ``target``; surface the worker's outcome.

        Returns ``{applied, ok, failures}``: the applied counts plus the worker's
        real success flag and its per-item ``failures`` list. ``ok`` is never
        forced true — if the worker reports failures (or an explicit ``ok:false``),
        the merge is not reported as silently successful.
        """
        wire = annotation_record_to_wire(record)
        structured = self._call_worker_tool(
            target, _APPLY_TOOL, {"record": wire}
        ) or {}
        applied = structured.get("applied") or {}
        counts = {
            "names": int(applied.get("names", 0)),
            "comments": int(applied.get("comments", 0)),
            "types": int(applied.get("types", 0)),
        }
        raw_failures = structured.get("failures")
        failures = (
            list(raw_failures) if isinstance(raw_failures, (list, tuple)) else []
        )
        worker_ok = structured.get("ok")
        ok = (True if worker_ok is None else bool(worker_ok)) and not failures
        return {"applied": counts, "ok": ok, "failures": failures}

    def _snapshot(self, target: SessionView) -> Dict[str, Any]:
        """Snapshot ``target`` to its canonical merged path; return ``{path, size}``.

        allow an explicit destination and confirm the write survived the
        live working files.
        """
        dest = _canonical_snapshot_path(target)
        structured = self._call_worker_tool(
            target, _SNAPSHOT_TOOL, {"path": dest}
        )
        structured = structured or {}
        return {
            "path": structured.get("path", dest),
            "size": int(structured.get("size", 0)),
        }

    # -- worker call helper --------------------------------------------------

    def _call_worker_tool(
        self, session: SessionView, name: str, arguments: Mapping[str, Any]
    ) -> Optional[Mapping[str, Any]]:
        """Forward one worker ``tools/call`` and return its ``structuredContent``.

        Raises :class:`MergeError` when the endpoint is unreachable, returns no
        response, or the tool itself reports an ``isError`` result.
        """
        frame = {
            "jsonrpc": "2.0",
            "id": next(self._inner_ids),
            "method": "tools/call",
            "params": {"name": name, "arguments": dict(arguments)},
        }
        try:
            response = self._client.forward(
                host=session.host,
                port=session.port,
                frame=frame,
                token=session.token,
            )
        except Exception as exc:  # noqa: BLE001 — transport failure → merge-level
            raise MergeError(
                f"failed calling '{name}' on session '{session.session_id}': {exc}"
            ) from exc
        if response is None:
            raise MergeError(
                f"session '{session.session_id}' returned no response to '{name}'"
            )
        error = response.get("error")
        if error is not None:
            raise MergeError(
                f"session '{session.session_id}' error on '{name}': "
                f"{error.get('message', 'worker error')}"
            )
        result = response.get("result") or {}
        if result.get("isError"):
            raise MergeError(
                f"tool '{name}' failed on session '{session.session_id}'"
            )
        return result.get("structuredContent")


# -- module helpers --------------------------------------------------------- #


def _as_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _str_tuple(value: Any) -> Tuple[str, ...]:
    """Coerce a list-of-strings argument into a tuple (non-strings dropped)."""
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def _agreed_provenance(
    records: Sequence[Tuple[str, AnnotationRecord]],
) -> Tuple[Optional[str], Optional[int]]:
    """The single ``(sha256, imagebase)`` the source records agree on.

    :func:`reconcile` has already refused any disagreement among these records, so
    at most one distinct non-``None`` value exists for each field; this surfaces it
    (or ``None`` when no source declared it) as the provenance the write target
    must match.
    """
    provenances: List[Provenance] = [record.provenance for _, record in records]
    sha: Optional[str] = None
    imagebase: Optional[int] = None
    for prov in provenances:
        if prov.input_sha256 is not None:
            sha = prov.input_sha256
        if prov.imagebase is not None:
            imagebase = prov.imagebase
    return sha, imagebase


def _path_matches(path: str, session: SessionView) -> bool:
    """Whether ``session`` was opened from ``path`` (exact or basename match)."""
    input_path = getattr(session, "input_path", "") or ""
    if not path or not input_path:
        return False
    if os.path.normcase(input_path) == os.path.normcase(path):
        return True
    return os.path.basename(input_path) == os.path.basename(path)


def _canonical_snapshot_path(target: SessionView) -> str:
    """The default ``<input>.merged.i64`` destination for an applied merge."""
    input_path = getattr(target, "input_path", "") or "target"
    root, _ext = os.path.splitext(input_path)
    return f"{root}{_MERGED_SUFFIX}"


__all__ = ["MergeOrchestrator", "MergeRequest", "MergeError"]
